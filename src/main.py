import uvicorn
from fastapi import FastAPI

from mcp_server.server import mcp

app = FastAPI(
    title="Agentic K-SecOps",
    description="MCP server for infrastructure security and compliance auditing",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.mount("/mcp", mcp.streamable_http_app())


def run_stdio() -> None:
    """Entry point for Cursor / Claude Desktop stdio transport."""
    mcp.run(transport="stdio")


def run_http(host: str = "0.0.0.0", port: int = 8000, reload: bool = False) -> None:
    uvicorn.run("main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    run_stdio()
