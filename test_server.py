from fastmcp import FastMCP
from fastmcp_oauth import GoogleOAuth, require_auth
import os


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


if __name__ == "__main__":  
    port = int(os.environ.get("PORT", 8000))  
    # Start an HTTP server  
    mcp.run(transport="http", host="0.0.0.0", port=port)