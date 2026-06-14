import asyncio
import glob
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests as _requests
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
import secrets

ANSI_ESCAPE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "eset-keygen-config.json"
_WEB_ONLY_KEYS = {"proxy_source_url", "use_proxy_pool"}
_lock = asyncio.Lock()

app = FastAPI(title="ESET KeyGen Web")

WEB_PASSWORD = os.environ.get("ETKG_PASSWORD", "")
# Random token valid for this server process; re-login required after restart
_SESSION_TOKEN = secrets.token_hex(32)

VALID_MODES = {"key", "account", "small-business-key", "advanced-key", "protecthub-account"}
VALID_BROWSERS = {"auto-detect-browser", "chrome", "firefox", "waterfox", "edge"}
VALID_EMAIL_APIS = {"guerrillamail", "1secmail", "mailticking", "fakemail", "inboxes", "emailfake", "incognitomail"}

BROWSER_CANDIDATES = {
    "chrome":   ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"],
    "firefox":  ["firefox"],
    "waterfox": ["waterfox"],
    "edge":     ["microsoft-edge", "microsoft-edge-stable"],
}
BROWSER_LABELS = {
    "chrome":              "Google Chrome / Chromium",
    "firefox":             "Mozilla Firefox",
    "waterfox":            "Waterfox",
    "edge":                "Microsoft Edge",
    "auto-detect-browser": "Auto-detect",
}

# In-memory proxy pool: list of "scheme:host:port:user:pass" strings
_proxy_pool: list[str] = []
_proxy_last_updated: float = 0.0
_proxy_source_url: str = ""

_current_proc: Optional[asyncio.subprocess.Process] = None


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

def check_auth(request: Request):
    """For API endpoints — returns 401 JSON so the JS can redirect."""
    if not WEB_PASSWORD:
        return
    token = request.cookies.get("session")
    if not token or not secrets.compare_digest(token, _SESSION_TOKEN):
        raise HTTPException(status_code=401, detail="Non autenticato")


def check_auth_page(request: Request):
    """For HTML pages — redirects to /login."""
    if not WEB_PASSWORD:
        return
    token = request.cookies.get("session")
    if not token or not secrets.compare_digest(token, _SESSION_TOKEN):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER,
                            headers={"Location": "/login"})


_LOGIN_HTML = """<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ESET KeyGen — Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem;
            padding: 2rem 2.5rem; width: 100%; max-width: 360px; }
    h1 { font-size: 1.2rem; color: #60a5fa; margin-bottom: 0.25rem; }
    .sub { font-size: 0.78rem; color: #475569; margin-bottom: 1.75rem; }
    label { font-size: 0.7rem; color: #64748b; text-transform: uppercase;
            letter-spacing: 0.07em; display: block; margin-bottom: 0.3rem; }
    input[type="password"] {
      width: 100%; background: #0f172a; color: #e2e8f0;
      border: 1px solid #334155; padding: 0.5rem 0.75rem;
      border-radius: 0.375rem; font-size: 0.9rem; outline: none;
      margin-bottom: 1.25rem;
    }
    input[type="password"]:focus { border-color: #3b82f6; }
    button { width: 100%; background: #3b82f6; color: #fff; border: none;
             padding: 0.55rem; border-radius: 0.375rem; font-size: 0.9rem;
             font-weight: 500; cursor: pointer; }
    button:hover { background: #2563eb; }
    .err { color: #f87171; font-size: 0.8rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ESET KeyGen</h1>
    <p class="sub">Inserisci la password per accedere</p>
    {error}
    <form method="post" action="/login">
      <label for="pwd">Password</label>
      <input type="password" id="pwd" name="password" autofocus autocomplete="current-password">
      <button type="submit">Accedi</button>
    </form>
  </div>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(error: str = ""):
    msg = '<p class="err">Password errata.</p>' if error else ""
    return _LOGIN_HTML.replace("{error}", msg)


@app.post("/login")
async def login_submit(password: str = Form(...)):
    if WEB_PASSWORD and secrets.compare_digest(password, WEB_PASSWORD):
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie("session", _SESSION_TOKEN, httponly=True, samesite="lax")
        return resp
    return RedirectResponse(url="/login?error=1", status_code=303)


@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session")
    return resp


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

@app.get("/", response_class=HTMLResponse, dependencies=[Depends(check_auth_page)])
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


class WebConfig(BaseModel):
    mode: str = "key"
    browser: str = "chrome"
    email_api: str = "emailfake"
    repeat: int = 1
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
    proxy_source_url: str = ""


def _read_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_config(data: dict):
    CONFIG_PATH.write_text(json.dumps(data, indent=4), encoding="utf-8")


@app.get("/browsers", dependencies=[Depends(check_auth)])
def get_browsers():
    found = []
    for value, bins in BROWSER_CANDIDATES.items():
        if any(shutil.which(b) for b in bins):
            found.append({"value": value, "label": BROWSER_LABELS[value]})
    found.append({"value": "auto-detect-browser", "label": BROWSER_LABELS["auto-detect-browser"]})
    return found


@app.get("/config", dependencies=[Depends(check_auth)])
async def get_config():
    raw = _read_config()
    # Map main.py keys → WebConfig field names
    return {
        "mode":                    raw.get("Mode of operation", "key"),
        "browser":                 raw.get("Browser", "chrome"),
        "email_api":               raw.get("Email API", "emailfake"),
        "repeat":                  raw.get("repeat", 1),
        "no_headless":             raw.get("no_headless", False),
        "custom_browser_location": raw.get("custom_browser_location", ""),
        "custom_email_api":        raw.get("custom_email_api", False),
        "skip_webdriver_menu":     raw.get("skip_webdriver_menu", True),
        "skip_update_check":       raw.get("skip_update_check", True),
        "disable_progress_bar":    raw.get("disable_progress_bar", True),
        "disable_output_file":     raw.get("disable_output_file", False),
        "output_file":             raw.get("output_file", ""),
        "proxy_file":              raw.get("proxy_file", ""),
        "disable_logging":         raw.get("disable_logging", True),
        "use_proxy_pool":          raw.get("use_proxy_pool", False),
        "proxy_source_url":        raw.get("proxy_source_url", ""),
    }


@app.post("/config", dependencies=[Depends(check_auth)])
async def save_config(cfg: WebConfig):
    raw = _read_config()
    # Map WebConfig fields → main.py config keys
    raw["Mode of operation"] = cfg.mode
    raw["Browser"]           = cfg.browser
    raw["Email API"]         = cfg.email_api
    raw["repeat"]            = cfg.repeat
    raw["no_headless"]             = cfg.no_headless
    raw["custom_browser_location"] = cfg.custom_browser_location
    raw["custom_email_api"]        = cfg.custom_email_api
    raw["skip_webdriver_menu"]     = cfg.skip_webdriver_menu
    raw["skip_update_check"]       = cfg.skip_update_check
    raw["disable_progress_bar"]    = cfg.disable_progress_bar
    raw["disable_output_file"]     = cfg.disable_output_file
    raw["output_file"]             = cfg.output_file
    raw["proxy_file"]              = cfg.proxy_file
    raw["disable_logging"]         = cfg.disable_logging
    raw["use_proxy_pool"]          = cfg.use_proxy_pool
    raw["proxy_source_url"]        = cfg.proxy_source_url
    _write_config(raw)
    return {"ok": True}


@app.post("/stop", dependencies=[Depends(check_auth)])
async def stop_run():
    global _current_proc
    if _current_proc and _current_proc.returncode is None:
        _current_proc.terminate()
        return {"ok": True}
    return {"ok": False, "detail": "Nessun processo in esecuzione"}


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

    def _build_base_cmd() -> list[str]:
        cmd = [sys.executable, str(BASE_DIR / "main.py")]
        cmd.append(f"--{config.mode}")
        cmd.append(f"--{config.browser}")
        cmd.extend(["--email-api", config.email_api])
        cmd.append("--no-logo")
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
        return cmd

    async def _run_once(cmd: list[str]):
        global _current_proc
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(BASE_DIR),
        )
        _current_proc = proc
        async for raw in proc.stdout:
            line = ANSI_ESCAPE.sub("", raw.decode("utf-8", errors="replace")).rstrip()
            if line:
                yield f"data: {line}\n\n"
        await proc.wait()
        _current_proc = None

    async def stream():
        async with _lock:
            # When proxy pool is active with repeat > 1, run N separate subprocesses
            # so each iteration gets a fresh, distinct proxy.
            use_pool = config.use_proxy_pool and bool(_proxy_pool)
            iterations = config.repeat if use_pool else 1
            pool_snapshot = list(_proxy_pool) if use_pool else []
            last_proxy: Optional[str] = None

            try:
                for i in range(iterations):
                    tmp_proxy_file = None
                    cmd = _build_base_cmd()

                    if use_pool:
                        # Pick a proxy different from the previous one
                        candidates = [p for p in pool_snapshot if p != last_proxy] or pool_snapshot
                        proxy = random.choice(candidates)
                        last_proxy = proxy
                        tmp_proxy_file = _write_single_proxy(proxy)
                        cmd.extend(["--proxy-file", tmp_proxy_file])
                        host = proxy.split(":")[1]
                        yield f"data: [PROXY] Ripetizione {i+1}/{iterations} — proxy: {host}\n\n"
                    else:
                        if config.repeat > 1:
                            cmd.extend(["--repeat", str(config.repeat)])
                        if config.proxy_file:
                            cmd.extend(["--proxy-file", config.proxy_file])

                    try:
                        async for chunk in _run_once(cmd):
                            yield chunk
                    finally:
                        if tmp_proxy_file:
                            try:
                                os.unlink(tmp_proxy_file)
                            except OSError:
                                pass
            finally:
                _current_proc = None

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


def _script_files() -> list[Path]:
    return [
        Path(p) for p in sorted(
            glob.glob(str(BASE_DIR / "*.txt")), key=os.path.getmtime, reverse=True
        )
        if _SCRIPT_FILE_RE.search(Path(p).name)
    ]


@app.delete("/files/{filename}", dependencies=[Depends(check_auth)])
async def delete_file(filename: str):
    path = BASE_DIR / filename
    if not path.resolve().parent == BASE_DIR.resolve():
        return JSONResponse(status_code=400, content={"error": "invalid path"})
    if not _SCRIPT_FILE_RE.search(filename):
        return JSONResponse(status_code=400, content={"error": "not a script output file"})
    try:
        path.unlink()
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "file not found"})
    return {"ok": True}


@app.delete("/files/{filename}/entries/{index}", dependencies=[Depends(check_auth)])
async def delete_entry(filename: str, index: int):
    path = BASE_DIR / filename
    if not path.resolve().parent == BASE_DIR.resolve():
        return JSONResponse(status_code=400, content={"error": "invalid path"})
    if not _SCRIPT_FILE_RE.search(filename):
        return JSONResponse(status_code=400, content={"error": "not a script output file"})
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "file not found"})
    blocks = [b for b in text.split(_SEPARATOR) if b.strip()]
    if index < 0 or index >= len(blocks):
        return JSONResponse(status_code=404, content={"error": "entry not found"})
    blocks.pop(index)
    new_text = (_SEPARATOR + "\n").join(b.lstrip("\n") for b in blocks)
    if new_text.strip():
        path.write_text(new_text, encoding="utf-8")
    else:
        path.unlink()
    return {"ok": True}


@app.delete("/files", dependencies=[Depends(check_auth)])
async def delete_all_files():
    for p in _script_files():
        try:
            p.unlink()
        except OSError:
            pass
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=False)
