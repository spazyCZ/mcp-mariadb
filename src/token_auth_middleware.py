# token_auth_middleware.py
# Simple token authentication middleware for MCP server

from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

class TokenAuthMiddleware(BaseHTTPMiddleware):
    """
    Require a shared token. If MCP_TOKEN is not set (None/empty) middleware is a no-op.
    Looks for either:
      - Authorization: Bearer <token>
      - x-mcp-token: <token>
    """

    def __init__(self, app, token: Optional[str] = None):
        super().__init__(app)
        self.token = token

    async def dispatch(self, request: Request, call_next):
        # If no token configured, allow all requests (server-side opt-out)
        if not self.token:
            return await call_next(request)

        auth_header = request.headers.get("authorization")
        token_header = request.headers.get("x-mcp-token")

        token_value = None
        if auth_header:
            # Accept both "Bearer <token>" and bare token
            if auth_header.lower().startswith("bearer "):
                token_value = auth_header.split(" ", 1)[1].strip()
            else:
                token_value = auth_header.strip()
        elif token_header:
            token_value = token_header.strip()

        if token_value != self.token:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        return await call_next(request)
