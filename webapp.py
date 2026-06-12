import asyncio
import os
import re
import sys
from pathlib import Path

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


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(check_auth)])
async def index():
    return (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


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

    async def stream():
        async with _lock:
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
            if config.proxy_file:
                cmd.extend(["--proxy-file", config.proxy_file])
            if config.disable_logging:
                cmd.append("--disable-logging")

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
            yield "data: __DONE__\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=False)
