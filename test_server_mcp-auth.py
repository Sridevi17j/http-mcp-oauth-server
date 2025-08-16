from mcpauth.config import AuthServerType
from mcpauth.utils import fetch_server_config
from mcp.server.fastmcp import FastMCP
from mcpauth import MCPAuth
from mcpauth.types import ResourceServerConfig, ResourceServerMetadata
from datetime import datetime
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Mount
from starlette.responses import JSONResponse



# Fetch authorization server metadata
auth_server_config = fetch_server_config(
    "https://tidy-wren-43.clerk.accounts.dev/",
    AuthServerType.OIDC  # or AuthServerType.OAUTH
)
mcp = FastMCP("ClerkMCPServer")

resource_id = "http://localhost:8000"  # Use your actual server URL

mcp_auth = MCPAuth(
    protected_resources=ResourceServerConfig(
        metadata=ResourceServerMetadata(
            resource=resource_id,
            authorization_servers=[auth_server_config],
            scopes_supported=["read", "write", "admin"]
        )
    )
)

bearer_auth = mcp_auth.bearer_auth_middleware("jwt", 
    resource="http://localhost:8000",  # Specify which resource this endpoint belongs to
    audience="http://localhost:8000",  # Enable audience validation for security
    required_scopes=["read", "write"] 
)

# Configure Bearer auth middleware for JWT validation
bearer_auth = mcp_auth.bearer_auth_middleware(
    "jwt",
    resource=resource_id,
    audience=resource_id,  # Enable audience validation
    required_scopes=["read"]  # Require at least 'read' scope
)

@mcp.tool()
async def get_time() -> str:
    """Get the current time (requires 'read' scope)"""
    auth_info = mcp_auth.auth_info
    return f"Current time: {datetime.now().isoformat()}"
	
	
app = Starlette(
    routes=[
        # Mount the MCP server with Bearer auth middleware
        Mount('/', app=mcp.sse_app(), middleware=[Middleware(bearer_auth)]),
        # Mount the metadata router for OAuth discovery
        *mcp_auth.resource_metadata_router().routes,
    ])
	
	
if __name__ == "__main__":
    import uvicorn
    print("Starting MCP Server with OAuth on http://localhost:8000")
    print("Protected resource metadata available at: /.well-known/oauth-protected-resource/mcp")
    print("Health check available at: /health")
    uvicorn.run(app, host="0.0.0.0", port=8000)