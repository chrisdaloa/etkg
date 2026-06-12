import asyncio
import os
import re
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

ANSI_ESCAPE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
BASE_DIR = Path(__file__).parent
_lock = asyncio.Lock()

app = FastAPI(title="ESET KeyGen Web")
security = HTTPBasic(auto_error=False)

WEB_PASSWORD = os.environ.get("ETKG_PASSWORD", "")

VALID_MODES = {"key", "account", "small-business-key", "advanced-key", "protecthub-account"}
VALID_EMAIL_APIS = {"guerrillamail", "1secmail", "mailticking", "fakemail", "inboxes", "emailfake", "incognitomail"}


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


@app.get("/run", dependencies=[Depends(check_auth)])
async def run(mode: str = "key", email_api: str = "emailfake"):
    if mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail=f"Modalità non valida: {mode}")
    if email_api not in VALID_EMAIL_APIS:
        raise HTTPException(status_code=400, detail=f"Email API non valida: {email_api}")
    if _lock.locked():
        raise HTTPException(status_code=409, detail="Uno script è già in esecuzione, riprova tra poco.")

    async def stream():
        async with _lock:
            cmd = [
                sys.executable, str(BASE_DIR / "main.py"),
                f"--{mode}",
                "--email-api", email_api,
                "--chrome",
                "--skip-update-check",
                "--skip-webdriver-menu",
                "--no-logo",
                "--disable-logging",
            ]
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
