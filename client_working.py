"""
Working MCP OAuth Client using Client Credentials flow
Based on your original client.py + OAuth token authentication
No browser required - uses client credentials flow
"""

import os
import asyncio
import requests
from typing import Optional
from anthropic import Anthropic
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv('env')

class MCPOAuthClient:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.anthropic = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.session: Optional[ClientSession] = None    
        self.tools = []
        self.client_context = None
        self.session_context = None
        self.access_token = None
        
        # Auth0 credentials
        self.domain = os.environ.get("AUTH0_DOMAIN")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID")
        self.client_secret = os.environ.get("AUTH0_CLIENT_SECRET")
        self.audience = os.environ.get("AUTH0_AUDIENCE")

    def get_access_token(self) -> bool:
        """Get access token using client credentials flow"""
        print("Getting access token from Auth0...")
        
        try:
            token_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'audience': self.audience,
                'grant_type': 'client_credentials'
            }
            
            response = requests.post(
                f"https://{self.domain}/oauth/token",
                json=token_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                token_response = response.json()
                self.access_token = token_response.get('access_token')
                if self.access_token:
                    print(f"SUCCESS: Access token obtained: {self.access_token[:30]}...")
                    return True
            
            print(f"FAILED: Token request failed - {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
        except Exception as e:
            print(f"ERROR: Token generation failed: {e}")
            return False

    async def connect(self):
        """Connect to the streamable HTTP MCP server"""
        print(f"Connecting to MCP server at {self.server_url}")
        
        try:
            # Connect to the streamable HTTP server
            self.client_context = streamablehttp_client(self.server_url)
            read_stream, write_stream, _ = await self.client_context.__aenter__()
            
            # Create a session using the client streams
            self.session_context = ClientSession(read_stream, write_stream)
            self.session = await self.session_context.__aenter__()
            
            # Initialize the session
            await self.session.initialize()
            
            # Get available tools
            resp = await self.session.list_tools()
            self.tools = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.inputSchema,
                }
                for t in resp.tools
            ]
            
            print(f"Connected! Available tools: {[t['name'] for t in self.tools]}")
            return True
            
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    async def process_query(self, query: str) -> str:
        """Process a user query using Claude with available MCP tools"""
        print(f"Processing query: {query}")
        
        # Send message to Claude with tool list
        claude_resp = self.anthropic.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": query}],
            tools=self.tools,
        )

        output = []
        
        for chunk in claude_resp.content:
            if chunk.type == "text":
                output.append(chunk.text)
            elif chunk.type == "tool_use":
                name, args = chunk.name, chunk.input
                print(f"Calling tool: {name} with args: {args}")
                
                # Add access token if using OAuth-protected tool
                if name == "extract_web_content_oauth" and self.access_token:
                    args["access_token"] = self.access_token
                
                # Call the MCP tool
                result = await self.session.call_tool(name, args)
                print(f"Tool result: {result.content}")
                
                output.append(f"\n[Tool Result from {name}]\n{result.content[0].text}")

        return "\n".join(output)

    async def test_oauth_functionality(self):
        """Test OAuth functionality"""
        print("\nTesting OAuth functionality...")
        
        # Test 1: Token validation
        if self.access_token:
            print("1. Testing token validation...")
            result = await self.session.call_tool("validate_token", {
                "access_token": self.access_token
            })
            validation_response = result.content[0].text
            print(f"Token validation result: {validation_response[:150]}...")
            
            # Check if token validation passed
            if '"valid": true' in validation_response:
                print("✅ Token validation: PASSED")
                token_valid = True
            else:
                print("❌ Token validation: FAILED")
                token_valid = False
            
            # Test 2: OAuth-protected content extraction
            print("\n2. Testing OAuth-protected content extraction...")
            result2 = await self.session.call_tool("extract_web_content_oauth", {
                "url": "https://httpbin.org/html",
                "access_token": self.access_token
            })
            extraction_response = result2.content[0].text
            print(f"OAuth extraction result: {extraction_response[:200]}...")
            
            # Check if extraction succeeded
            if '"success": true' in extraction_response:
                print("✅ OAuth extraction: PASSED")
                extraction_valid = True
            else:
                print("❌ OAuth extraction: FAILED")
                extraction_valid = False
            
            # Final verdict
            if token_valid and extraction_valid:
                print("\n✅ OAuth functionality VERIFIED - All tests passed!")
                return True
            else:
                print("\n❌ OAuth functionality FAILED - Authentication not working!")
                print("This indicates a configuration issue with Auth0 or network connectivity.")
                return False
        else:
            print("❌ No access token available for testing")
            return False

    async def chat_loop(self):
        """Interactive chat loop for testing"""
        print("\nInteractive Chat Mode - Ask questions about web content!")
        print("Examples:")
        print("  - 'Extract content from https://example.com'")
        print("  - 'Get the title of https://github.com'")
        print("Type 'exit' to quit\n")
        
        while True:
            user_input = input("You: ").strip()
            if user_input.lower() in ("exit", "quit"):
                break
                
            try:
                response = await self.process_query(user_input)
                print("Assistant:", response)
                print("-" * 50)
            except Exception as e:
                print(f"Error: {e}")

    async def close(self):
        """Clean up connections"""
        if self.session_context:
            await self.session_context.__aexit__(None, None, None)
        if self.client_context:
            await self.client_context.__aexit__(None, None, None)
        print("Disconnected from MCP server")

async def main():
    """Main entry point"""
    print("MCP OAuth Client (Working Version - No Browser)")
    print("Make sure the server is running at http://localhost:8000/mcp")
    print()
    
    client = MCPOAuthClient("http://localhost:8000/mcp")
    
    try:
        # Step 1: Get OAuth token
        if not client.get_access_token():
            print("Failed to get access token. Check Auth0 configuration.")
            return
        
        # Step 2: Connect to server
        if not await client.connect():
            print("Failed to connect to MCP server.")
            return
        
        # Step 3: Test OAuth functionality
        oauth_working = await client.test_oauth_functionality()
        
        if not oauth_working:
            print("\n🚨 STOPPING: OAuth is not working properly!")
            print("Please check:")
            print("1. Auth0 configuration is correct")
            print("2. Network connectivity to Auth0")
            print("3. Server is running the OAuth-enabled version")
            return
        
        # Step 4: Interactive chat (only if OAuth works)
        await client.chat_loop()
        
    except KeyboardInterrupt:
        print("\nGoodbye!")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())