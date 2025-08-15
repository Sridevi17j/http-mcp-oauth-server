"""  
Pure FastMCP server with Clerk-based authentication and StreamableHTTP transport.  
No FastAPI dependency - uses only FastMCP's built-in capabilities.  
"""  
  
import os  
import time  
from datetime import datetime  
from fastmcp import FastMCP  
from fastmcp.server.auth import BearerAuthProvider  
from starlette.requests import Request  
from starlette.responses import JSONResponse, PlainTextResponse  
import dotenv  
  
dotenv.load_dotenv()  
  
# Configuration - use environment variables or defaults  
ISSUER = os.getenv("CLERK_ISSUER", "https://tidy-wren-43.clerk.accounts.dev")  
AUDIENCE = os.getenv("CLERK_AUDIENCE", "3MjfL6Ioir3mViNC")  
CLIENT_SECRET = os.getenv("CLERK_CLIENT_SECRET","0sPPxTdU1IZf8BOBlAuTokthO4cR54z1")  
BASE_URL = os.getenv("BASE_URL", "https://http-mcp-oauth-server-2.onrender.com")  
  
# Configure Clerk-based authentication  
auth = BearerAuthProvider(  
    jwks_uri=f"{ISSUER}/.well-known/jwks.json",  
    issuer=ISSUER,  
    audience=AUDIENCE,  
)  
  
# Create FastMCP server with authentication  
mcp = FastMCP(name="MCP OAuth Server", auth=auth)  
  
# Add tools  
@mcp.tool  
def hello(name: str) -> str:  
    """A protected greeting tool."""  
    return f"Hello, {name}! This is a protected endpoint."  
  
@mcp.tool  
def add_numbers(a: int, b: int) -> int:  
    """Add two numbers together."""  
    return a + b  
  
# Add custom HTTP routes for OAuth discovery  
@mcp.custom_route("/health", methods=["GET"])  
def health_check(request: Request) -> PlainTextResponse:  
    return PlainTextResponse("OK", status_code=200)  
  
@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])  
def oauth_metadata(request: Request) -> JSONResponse:  
    """OAuth 2.1 Authorization Server Metadata."""  
    return JSONResponse({  
        "issuer": ISSUER,  
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",  
        "token_endpoint": f"{ISSUER}/oauth/token",  
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",  
        "registration_endpoint": f"{BASE_URL}/register",  
        "response_types_supported": ["code"],  
        "code_challenge_methods_supported": ["S256"],  
        "token_endpoint_auth_methods_supported": ["client_secret_post"],  
        "grant_types_supported": ["authorization_code", "refresh_token"],  
    })  
  
@mcp.custom_route("/.well-known/openid-configuration", methods=["GET"])  
def openid_config(request: Request) -> JSONResponse:  
    """OpenID Connect Discovery endpoint."""  
    return JSONResponse({  
        "issuer": ISSUER,  
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",  
        "token_endpoint": f"{ISSUER}/oauth/token",  
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",  
        "response_types_supported": ["code"],  
        "subject_types_supported": ["public"],  
        "id_token_signing_alg_values_supported": ["RS256"],  
    })  
  
@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])  
def oauth_protected_resource(request: Request) -> JSONResponse:  
    """OAuth 2.1 Protected Resource Metadata."""  
    return JSONResponse({  
        "resource": BASE_URL,  
        "authorization_servers": [ISSUER],  
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",  
        "bearer_methods_supported": ["header"],  
        "resource_documentation": f"{BASE_URL}/docs",  
    })  
  
@mcp.custom_route("/register", methods=["POST"])  
async def register(request: Request) -> JSONResponse:  
    """OAuth 2.1 Dynamic Client Registration endpoint."""  
    try:  
        data = await request.json()  
          
        # Generate client credentials  
        client_id = AUDIENCE  
        client_secret = CLIENT_SECRET  
        now = int(time.time())  
          
        # Build the response according to OAuth 2.0 Dynamic Client Registration spec  
        response_data = {  
            "client_id": client_id,  
            "client_secret": client_secret,  
            "client_id_issued_at": now,  
            "client_secret_expires_at": 0,  # 0 means no expiration  
            "redirect_uris": data.get("redirect_uris", []),  
            "token_endpoint_auth_method": data.get("token_endpoint_auth_method", "client_secret_post"),  
            "grant_types": data.get("grant_types", ["authorization_code"]),  
            "response_types": data.get("response_types", ["code"]),  
            "client_name": data.get("client_name", ""),  
            "scope": data.get("scope", ""),  
        }  
          
        return JSONResponse(response_data, status_code=201)  
    except Exception as e:  
        return JSONResponse(  
            {"error": "Invalid JSON body", "details": str(e)},   
            status_code=400  
        )  
  
if __name__ == "__main__":  
    # Run with StreamableHTTP transport  
    mcp.run(  
        transport="http",  # StreamableHTTP transport  
        host="0.0.0.0",  
        port=int(os.environ.get("PORT", 8000)),  
        log_level="debug"  
    )