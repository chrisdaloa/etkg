import asyncio
import glob
import os
import random
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests as _requests
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
import secrets

ANSI_ESCAPE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
BASE_DIR = Path(__file__).parent
_lock = asyncio.Lock()

app = FastAPI(title="ESET KeyGen Web")
security = HTTPBasic(auto_error=False)

WEB_PASSWORD = os.environ.get("ETKG_PASSWORD", "")

VALID_MODES = {"key", "account", "small-business-key", "advanced-key", "protecthub-account"}
VALID_BROWSERS = {"auto-detect-browser", "chrome", "firefox", "waterfox", "edge"}
VALID_EMAIL_APIS = {"guerrillamail", "1secmail", "mailticking", "fakemail", "inboxes", "emailfake", "incognitomail"}

# In-memory proxy pool: list of "scheme:host:port:user:pass" strings
_proxy_pool: list[str] = []
_proxy_last_updated: float = 0.0
_proxy_source_url: str = ""


# ── proxy helpers ──────────────────────────────────────────────────────────────

def _webshare_to_script_format(line: str) -> Optional[str]:
    """Convert Webshare line (ip:port:user:pass) to script format (scheme:ip:port:user:pass)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) == 4:                         # ip:port:user:pass  (Webshare default)
        return f"http:{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}"
    if len(parts) == 5:                         # scheme:ip:port:user:pass (already correct)
        return line
    return None


def _fetch_proxies(url: str) -> list[str]:
    resp = _requests.get(url, timeout=15)
    resp.raise_for_status()
    result = []
    for line in resp.text.splitlines():
        converted = _webshare_to_script_format(line)
        if converted:
            result.append(converted)
    return result


def _write_single_proxy(proxy: str) -> str:
    """Write one proxy line to a temp file and return the path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False,
                                      dir=str(BASE_DIR), prefix="proxy_run_")
    tmp.write(proxy + "\n")
    tmp.close()
    return tmp.name


# ── auth ───────────────────────────────────────────────────────────────────────

def check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if not WEB_PASSWORD:
        return
    if not credentials or not secrets.compare_digest(
        credentials.password.encode(), WEB_PASSWORD.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"},
        )


# ── models ─────────────────────────────────────────────────────────────────────

class RunConfig(BaseModel):
    mode: str = "key"
    browser: str = "chrome"
    email_api: str = "emailfake"
    repeat: int = Field(default=1, ge=1, le=50)
    no_headless: bool = False
    custom_browser_location: str = ""
    custom_email_api: bool = False
    skip_webdriver_menu: bool = True
    skip_update_check: bool = True
    disable_progress_bar: bool = True
    disable_output_file: bool = False
    output_file: str = ""
    proxy_file: str = ""
    disable_logging: bool = True
    use_proxy_pool: bool = False


class ProxyRefreshRequest(BaseModel):
    url: str


# ── routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, dependencies=[Depends(check_auth)])
async def index():
    return (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


@app.post("/proxies/refresh", dependencies=[Depends(check_auth)])
async def proxies_refresh(req: ProxyRefreshRequest):
    global _proxy_pool, _proxy_last_updated, _proxy_source_url
    if not req.url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL non valido")
    try:
        pool = await asyncio.get_event_loop().run_in_executor(None, _fetch_proxies, req.url)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Errore nel fetch: {e}")
    if not pool:
        raise HTTPException(status_code=502, detail="Nessun proxy valido trovato nella risposta")
    _proxy_pool = pool
    _proxy_last_updated = time.time()
    _proxy_source_url = req.url
    return {"count": len(_proxy_pool), "updated_at": _proxy_last_updated}


@app.get("/proxies/status", dependencies=[Depends(check_auth)])
async def proxies_status():
    return {
        "count": len(_proxy_pool),
        "updated_at": _proxy_last_updated,
        "source_url": _proxy_source_url,
    }


@app.post("/run", dependencies=[Depends(check_auth)])
async def run(config: RunConfig):
    if config.mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail=f"Modalità non valida: {config.mode}")
    if config.browser not in VALID_BROWSERS:
        raise HTTPException(status_code=400, detail=f"Browser non valido: {config.browser}")
    if config.email_api not in VALID_EMAIL_APIS:
        raise HTTPException(status_code=400, detail=f"Email API non valida: {config.email_api}")
    if _lock.locked():
        raise HTTPException(status_code=409, detail="Uno script è già in esecuzione, riprova tra poco.")
    if config.use_proxy_pool and not _proxy_pool:
        raise HTTPException(status_code=400, detail="Pool proxy vuoto — aggiorna prima la lista da Webshare.")

    async def stream():
        async with _lock:
            tmp_proxy_file = None
            cmd = [sys.executable, str(BASE_DIR / "main.py")]
            cmd.append(f"--{config.mode}")
            cmd.append(f"--{config.browser}")
            cmd.extend(["--email-api", config.email_api])
            cmd.append("--no-logo")

            if config.repeat > 1:
                cmd.extend(["--repeat", str(config.repeat)])
            if config.no_headless:
                cmd.append("--no-headless")
            if config.custom_browser_location:
                cmd.extend(["--custom-browser-location", config.custom_browser_location])
            if config.custom_email_api:
                cmd.append("--custom-email-api")
            if config.skip_webdriver_menu:
                cmd.append("--skip-webdriver-menu")
            if config.skip_update_check:
                cmd.append("--skip-update-check")
            if config.disable_progress_bar:
                cmd.append("--disable-progress-bar")
            if config.disable_output_file:
                cmd.append("--disable-output-file")
            if config.output_file:
                cmd.extend(["--output-file", config.output_file])
            if config.disable_logging:
                cmd.append("--disable-logging")

            if config.use_proxy_pool and _proxy_pool:
                proxy = random.choice(_proxy_pool)
                tmp_proxy_file = _write_single_proxy(proxy)
                cmd.extend(["--proxy-file", tmp_proxy_file])
                host = proxy.split(":")[1]
                yield f"data: [PROXY] Usando proxy: {host}\n\n"
            elif config.proxy_file:
                cmd.extend(["--proxy-file", config.proxy_file])

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=str(BASE_DIR),
                )
                async for raw in proc.stdout:
                    line = ANSI_ESCAPE.sub("", raw.decode("utf-8", errors="replace")).rstrip()
                    if line:
                        yield f"data: {line}\n\n"
                await proc.wait()
            finally:
                if tmp_proxy_file:
                    try:
                        os.unlink(tmp_proxy_file)
                    except OSError:
                        pass

            yield "data: __DONE__\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── output files ───────────────────────────────────────────────────────────────

_ENTRY_PATTERNS = [
    ("email",    re.compile(r"Account Email:\s*(.+)", re.IGNORECASE)),
    ("password", re.compile(r"Account Password:\s*(.+)", re.IGNORECASE)),
    ("license",  re.compile(r"License Name:\s*(.+)", re.IGNORECASE)),
    ("key",      re.compile(r"License Key:\s*(.+)", re.IGNORECASE)),
    ("expiry",   re.compile(r"License Out Date:\s*(.+)", re.IGNORECASE)),
]
_SEPARATOR = "-" * 49
_SCRIPT_FILE_RE = re.compile(r"ESET (KEYS|ACCOUNTS)\.txt$", re.IGNORECASE)


def _is_script_output(text: str) -> bool:
    return _SEPARATOR in text and any(p.search(text) for _, p in _ENTRY_PATTERNS)


def _parse_entries(text: str) -> list[dict]:
    entries = []
    for block in text.split(_SEPARATOR):
        block = block.strip()
        if not block:
            continue
        entry = {}
        for line in block.splitlines():
            for key, pattern in _ENTRY_PATTERNS:
                m = pattern.match(line.strip())
                if m:
                    entry[key] = m.group(1).strip()
        if entry:
            entries.append(entry)
    return entries


@app.get("/files", dependencies=[Depends(check_auth)])
async def list_files():
    all_txt = glob.glob(str(BASE_DIR / "*.txt"))
    result = []
    for path in sorted(all_txt, key=os.path.getmtime, reverse=True):
        if not _SCRIPT_FILE_RE.search(Path(path).name):
            continue
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _is_script_output(text):
            continue
        result.append({"filename": Path(path).name, "entries": _parse_entries(text)})
        if len(result) == 5:
            break
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=False)
