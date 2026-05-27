"""
CyberScanner — Entry Point
FastAPI application. Phase 1: hello world to verify the stack is alive.
"""

from fastapi import FastAPI
from rich.console import Console

from api.routes import router as scans_router, ws_router

console = Console()

app = FastAPI(
    title="CyberScanner",
    description="Professional-grade cybersecurity scanner API",
    version="0.1.0",
)

app.include_router(scans_router)
app.include_router(ws_router)


@app.get("/")
async def root():
    return {"status": "ok", "message": "CyberScanner is running"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    console.print("[bold green]Starting CyberScanner...[/bold green]")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
