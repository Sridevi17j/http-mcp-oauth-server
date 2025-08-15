from fastmcp import FastMCP
from fastmcp_oauth import GoogleOAuth, require_auth

# Create server
mcp = FastMCP("My Server")

# Add Microsoft OAuth (3 lines!)
oauth = GoogleOAuth.from_env()
app = oauth.install(mcp)

# Protected tool
@mcp.tool()
@require_auth
async def get_user_info(ctx) -> str:
    user = ctx.auth.user
    return f"Hello {user.name}! Email: {user.email}"