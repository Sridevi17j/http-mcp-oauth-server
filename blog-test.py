import os
import sys
import logging
from datetime import datetime

from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import AnyHttpUrl

from fastmcp import FastMCP
from fastmcp.server.auth.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier

# Logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("fastmcp.server.auth.providers.jwt").setLevel(logging.DEBUG)

# ----- Auth setup -----
token_verifier = JWTVerifier(
    jwks_uri="https://dev-xrlojx8grz2bwyup.us.auth0.com/.well-known/jwks.json",
    issuer="https://dev-xrlojx8grz2bwyup.us.auth0.com/",
    audience="https://mcp-content-api",
)

auth = RemoteAuthProvider(
    token_verifier=token_verifier,
    authorization_servers=[AnyHttpUrl("https://dev-xrlojx8grz2bwyup.us.auth0.com")],
    resource_server_url="https://http-mcp-oauth-server-2.onrender.com/mcp",
)

mcp = FastMCP(name="Company API", auth=auth)

# ----- Tool -----
@mcp.tool
def test_str(name: str) -> str:
    print(f"Tool called at: {datetime.now()}", file=sys.stderr)
    return f"Hello, {name}!"

# ----- App and middleware -----
app = mcp.streamable_http_app()

class LogAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # The token is sent on the stream creating POST to /mcp
        if request.url.path == "/mcp" and request.method == "POST":
            auth = request.headers.get("authorization")
            if auth and auth.lower().startswith("bearer "):
                token = auth[len("bearer "):]
                # Print the full token for now since you asked to verify it
                # You can trim later to avoid leaking secrets in logs
                print(f"Access token: {token}", file=sys.stderr)
            else:
                print("No Authorization header on /mcp POST", file=sys.stderr)
        return await call_next(request)

app.add_middleware(LogAuthMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# ----- Runner -----
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    mcp.run(transport="http", host="0.0.0.0", port=8000)
