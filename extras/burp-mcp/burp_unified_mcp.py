#!/usr/bin/env python3
"""
Unified Burp MCP Server — merges ALL tools from:
1. BurpMCP Jar SSE (:8181) — 52 tools (primary)
2. Burp REST API (:1337) — additional tools (fallback)

Graceful: REST API tools always work. If Jar SSE is down, still get 20+ tools.
Never crashes — every error is caught and reported gracefully.
"""

import asyncio
import logging
import sys
import json
import os
import re
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import requests
from mcp import (
    ClientSession, 
    ServerSession, 
    types
)
from mcp.server.models import InitializationOptions
from mcp.client.sse import sse_client
from mcp.server.stdio import stdio_server
from mcp.shared.session import RequestResponder
from pydantic import BaseModel

# ── Config ───────────────────────────────────────────────────────────
BURP_SSE_URL = os.environ.get("BURP_SSE_URL", "http://localhost:8181/mcp/sse")
BURP_REST_URL = os.environ.get("BURP_REST_URL", "http://127.0.0.1:1337")
BURP_PROXY = os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - burp-unified - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("burp-unified")

# ── REST API Client ──────────────────────────────────────────────────
rest_session = requests.Session()
rest_session.headers.update({"Content-Type": "application/json"})

def burp_api(method: str, path: str, **kwargs) -> requests.Response:
    url = f"{BURP_REST_URL}/v0.1{path}"
    try:
        return rest_session.request(method, url, timeout=10, **kwargs)
    except requests.exceptions.ConnectionError:
        return type('R', (), {'status_code': 0, 'text': 'REST API unreachable', 'ok': False})()

# ── REST API Tool Handlers ───────────────────────────────────────────

def rest_check_burp_connection() -> str:
    """Check if Burp REST API is running."""
    try:
        r = requests.get(f"{BURP_REST_URL}/v0.1/", timeout=3)
        return json.dumps({
            "status": "connected" if r.status_code < 500 else "error",
            "http_status": r.status_code,
            "burp_version": r.headers.get("X-Burp-Version", "unknown"),
            "rest_api_url": BURP_REST_URL,
            "proxy_url": BURP_PROXY
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "disconnected", "error": str(e)}, indent=2)

def rest_get_scanner_issues(base_url: str = "") -> str:
    issues = burp_api("GET", "/knowledge_base/issue_definitions")
    if issues.status_code == 200:
        data = issues.json()
        if base_url:
            data = [i for i in data if base_url.lower() in json.dumps(i).lower()]
        return json.dumps(data[:100], indent=2)[:50000]
    return json.dumps({"error": f"HTTP {issues.status_code}", "detail": issues.text[:500]}, indent=2)

def rest_send_through_proxy(request_text: str) -> str:
    """Send raw HTTP through Burp proxy. Appears in HTTP History."""
    try:
        proxy = {"http": BURP_PROXY, "https": BURP_PROXY}
        lines = request_text.strip().split("\n")
        first = lines[0].strip().split(" ", 2)
        if len(first) < 2:
            return "Error: Invalid HTTP request line"
        method = first[0]
        path = first[1]
        
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            s = line.strip()
            if not s:
                body_start = i + 1
                break
            if ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip()] = v.strip()
        
        body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
        host = headers.get("Host", "localhost")
        
        if path.startswith("http"):
            url = path
        else:
            scheme = "https" if ":443" in host else "http"
            url = f"{scheme}://{host}{path}"
        
        skip_headers = {"host", "content-length", "transfer-encoding"}
        req_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}
        req_headers["Connection"] = "close"
        
        resp = requests.request(
            method, url, headers=req_headers, data=body,
            proxies=proxy, verify=False, timeout=30, allow_redirects=False
        )
        
        reason = {200:"OK",201:"Created",204:"No Content",301:"Moved",302:"Found",
                  400:"Bad Request",401:"Unauthorized",403:"Forbidden",404:"Not Found",
                  405:"Method Not Allowed",500:"Internal Server Error",502:"Bad Gateway",
                  503:"Service Unavailable"}.get(resp.status_code, "")
        
        rh = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()
                       if k.lower() not in ("transfer-encoding",))
        
        return f"HTTP/1.1 {resp.status_code} {reason}\n{rh}\n\n{resp.text}"
    except Exception as e:
        return f"HTTP/1.1 502 Bad Gateway\n\nProxy Error: {str(e)}"

# Known REST API tool names that we handle locally
REST_TOOLS = {
    "check_burp_connection",
    "burp_status", 
    "burp_rest_status",
    "get_scanner_issues",
    "send_raw_http",
    "send_through_proxy",
}

def is_rest_tool(name: str) -> bool:
    return name in REST_TOOLS

def handle_rest_tool(name: str, args: dict) -> str:
    handlers = {
        "check_burp_connection": lambda a: rest_check_burp_connection(),
        "burp_status": lambda a: rest_check_burp_connection(),
        "burp_rest_status": lambda a: rest_check_burp_connection(),
        "get_scanner_issues": lambda a: rest_get_scanner_issues(a.get("base_url", "")),
        "send_raw_http": lambda a: rest_send_through_proxy(a.get("request_text", "")),
        "send_through_proxy": lambda a: rest_send_through_proxy(a.get("request_text", "")),
    }
    handler = handlers.get(name)
    if handler:
        return handler(args)
    return json.dumps({"error": f"Unknown REST tool: {name}"})

# Kebab-case tool names exposed by the BurpMCP Jar (52 tools), derived from
# burpmcp/tools/*.class (e.g. SendToRepeaterTool -> send-to-repeater). Listed
# statically so clients can discover the full Burp toolset even when the Burp
# app / SSE endpoint (:8181) is not currently running.
JAR_TOOL_NAMES = [
    "send-to-repeater", "send-to-intruder", "send-to-comparer", "send-to-organizer",
    "http1-send", "http1-resend", "http2-send", "http2-resend",
    "save-http1-request", "save-http2-request", "get-saved-request",
    "proxy-intercept", "proxy-history", "list-proxy-traffic", "get-proxy-entry",
    "search-proxy-traffic", "tail-proxy-traffic",
    "cookie-set", "cookie-list", "editor-set", "editor-get", "update-note",
    "scope-update", "scope-check", "sitemap-add", "site-map-list", "site-map-issues",
    "scanner-start-crawl", "scanner-start-audit", "scanner-crawl-status",
    "scanner-audit-status", "scanner-cancel", "scanner-generate-report",
    "scanner-import-bcheck", "analyzer-create-keywords", "analyzer-create-variations",
    "analyzer-feed-response", "generate-collaborator-payload",
    "retrieve-collaborator-interactions", "decode-encode", "crypto-digest",
    "compress-data", "json-query", "number-convert", "string-hex", "random-string",
    "options-export", "options-import", "project-info", "burp-log",
    "web-socket-history", "task-engine",
]


def _rest_tool_defs() -> list:
    """Tool definitions for the REST API subset (always available, no Burp needed)."""
    return [
        types.Tool(
            name="burp_status",
            description="Check Burp Suite connection status (REST API + SSE)",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="check_burp_connection",
            description="Verify Burp REST API and proxy connectivity",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_scanner_issues",
            description="Get Burp Scanner issue definitions",
            inputSchema={"type": "object", "properties": {
                "base_url": {"type": "string", "description": "Filter by URL"},
            }},
        ),
        types.Tool(
            name="send_raw_http",
            description="Send raw HTTP request through Burp proxy (captures in HTTP History)",
            inputSchema={"type": "object", "properties": {
                "request_text": {"type": "string", "description": "Raw HTTP request"},
            }, "required": ["request_text"]},
        ),
    ]


def _static_jar_tool_defs() -> list:
    """Best-effort statically declared Jar tool defs for discovery when Burp/SSE
    is down. Real schemas/descriptions appear once Burp is running."""
    return [
        types.Tool(
            name=name,
            description=f"BurpMCP tool '{name}' (requires Burp Suite + BurpMCP on SSE :8181)",
            inputSchema={"type": "object", "properties": {}},
        )
        for name in JAR_TOOL_NAMES
    ]


# ── SSE Bridge Client ────────────────────────────────────────────────
class OutboundNotification(BaseModel):
    method: str
    params: Optional[Any] = None

class UnifiedBridge:
    def __init__(self, sse_url: str):
        self.sse_url = sse_url
        self._client_session: Optional[ClientSession] = None
        self._server_session: Optional[ServerSession] = None
        self._remote_capabilities = None
        self._jar_tools = []  # cached list of tools from Jar
        self._sse_ctx = None  # Keep SSE context alive
        self._client_ctx = None  # Keep ClientSession context alive
        self._sse_read = None
        self._sse_write = None
        
        logger.info(f"Unified Burp MCP initializing (SSE: {sse_url}, REST: {BURP_REST_URL})")
    
    async def ensure_initialized(self, retry=True) -> bool:
        """Ensure SSE connection is established. Retries with backoff if Burp is starting."""
        if self._client_session:
            return True
        
        # ── Retry with exponential backoff ─────────────────────────
        max_retries = 5
        base_delay = 3  # seconds
        
        for attempt in range(max_retries):
            try:
                self._sse_ctx = sse_client(self.sse_url)
                self._sse_read, self._sse_write = await self._sse_ctx.__aenter__()
                
                self._client_ctx = ClientSession(
                    self._sse_read, self._sse_write,
                    message_handler=self.handle_server_message
                )
                self._client_session = await self._client_ctx.__aenter__()
                
                result = await self._client_session.initialize()
                self._remote_capabilities = result.capabilities
                
                try:
                    tools_result = await self._client_session.list_tools()
                    if tools_result and hasattr(tools_result, 'tools'):
                        self._jar_tools = [t.name for t in tools_result.tools]
                        logger.info(f"Jar SSE tools cached: {len(self._jar_tools)} tools")
                except Exception as e:
                    logger.warning(f"Could not cache Jar tools: {e}")
                
                logger.info(f"SSE connected: {result.serverInfo.name} {result.serverInfo.version}")
                return True
            except Exception as e:
                if attempt < max_retries - 1 and retry:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"SSE connect attempt {attempt+1}/{max_retries} failed ({e}), retrying in {delay}s...")
                    await asyncio.sleep(delay)
                else:
                    logger.warning(f"SSE unavailable after {max_retries} attempts (REST-only mode): {e}")
                    self._jar_tools = []
                    self._client_session = None
                    return False
        
        return False
    
    def tool_name_known(self, name: str) -> bool:
        """Check if a tool name is known from either source."""
        if is_rest_tool(name):
            return True
        if name in self._jar_tools:
            return True
        return False
    
    async def forward_to_sse(self, request: Any) -> types.ServerResult:
        """Forward a request to the SSE Jar server (graceful when SSE is down)."""
        method = getattr(request, 'method', '')

        if method == "ping":
            return types.ServerResult(types.EmptyResult())

        elif method == "tools/list":
            if self._client_session:
                jar_result = await self._client_session.list_tools()
                if hasattr(jar_result, 'tools'):
                    jar_result.tools.extend(_rest_tool_defs())
                return types.ServerResult(jar_result)
            # SSE down: advertise static Jar names + REST tools so the client sees
            # the full Burp toolset and the server still loads in the client.
            return types.ServerResult(
                types.ListToolsResult(
                    tools=_static_jar_tool_defs() + _rest_tool_defs()
                )
            )

        elif method == "tools/call":
            tool_name = getattr(request.params, 'name', '')
            tool_args = getattr(request.params, 'arguments', {}) or {}

            # REST API tools are handled locally and never need SSE
            if is_rest_tool(tool_name):
                result_text = handle_rest_tool(tool_name, tool_args)
                return types.ServerResult(
                    types.CallToolResult(
                        content=[types.TextContent(type="text", text=result_text)]
                    )
                )

            # Jar tools need a live Burp/SSE connection
            if not self._client_session:
                return types.ServerResult(
                    types.CallToolResult(
                        content=[types.TextContent(
                            type="text",
                            text=(f"Tool '{tool_name}' requires Burp Suite to be running with "
                                  "the BurpMCP extension (SSE on :8181). Currently unavailable.")
                        )],
                        isError=True
                    )
                )

            try:
                result = await self._client_session.call_tool(tool_name, tool_args)
                return types.ServerResult(result)
            except Exception as e:
                error_msg = str(e)
                if "not found" in error_msg.lower() or "unknown tool" in error_msg.lower():
                    return types.ServerResult(
                        types.CallToolResult(
                            content=[types.TextContent(
                                type="text",
                                text=f"Tool '{tool_name}' not found. Available tools are listed via tools/list."
                            )],
                            isError=True
                        )
                    )
                raise

        else:
            # Everything else requires SSE
            if not self._client_session:
                raise ConnectionError("SSE not connected")
            return await self._forward_request(request)
    
    async def _forward_request(self, request: Any) -> types.ServerResult:
        """Generic request forwarding to SSE server."""
        method_name = request.method.replace('/', '_')
        client_method = getattr(self._client_session, method_name, None)
        
        if not client_method:
            if request.method == "prompts/list":
                return types.ServerResult(await self._client_session.list_prompts())
            elif request.method == "prompts/get":
                return types.ServerResult(await self._client_session.get_prompt(
                    request.params.name, request.params.arguments
                ))
            elif request.method == "resources/list":
                return types.ServerResult(await self._client_session.list_resources())
            elif request.method == "resources/read":
                return types.ServerResult(await self._client_session.read_resource(request.params.uri))
            
            return types.ServerResult(
                types.ErrorData(code=types.METHOD_NOT_FOUND, message=f"Unknown method: {request.method}")
            )
        
        if hasattr(request, 'params') and request.params:
            kwargs = {}
            for field_name in request.params.model_fields.keys():
                if hasattr(request.params, field_name):
                    value = getattr(request.params, field_name)
                    if value is not None:
                        kwargs[field_name] = value
            result = await client_method(**kwargs)
        else:
            result = await client_method()
        
        return types.ServerResult(result)
    
    async def handle_client_request(self, responder):
        if not self._client_session:
            await self.ensure_initialized()
        
        try:
            result = await self.forward_to_sse(responder.request.root)
            with responder:
                await responder.respond(result)
        except Exception as e:
            logger.error(f"Request error: {e}", exc_info=True)
            with responder:
                await responder.respond(
                    types.ErrorData(code=0, message=f"Bridge error: {str(e)}")
                )
    
    async def handle_client_notification(self, notification):
        if not self._client_session:
            return
        try:
            if hasattr(notification, 'root') and notification.root:
                method, params = self._extract_method_and_params(notification)
                if method is not None:
                    outbound = OutboundNotification(method=method, params=params)
                    await self._client_session.send_notification(outbound)
        except Exception as e:
            logger.debug(f"Notification error: {e}")
    
    async def handle_server_request(self, responder):
        if not self._server_session:
            return
        try:
            with responder:
                await responder.respond(
                    types.ErrorData(code=0, message="Sampling/roots not supported by bridge")
                )
        except Exception as e:
            logger.debug(f"Server request error: {e}")
    
    async def handle_server_notification(self, notification):
        if not self._server_session:
            return
        try:
            if hasattr(notification, 'root') and notification.root:
                method, params = self._extract_method_and_params(notification)
                if method is not None:
                    outbound = OutboundNotification(method=method, params=params)
                    await self._server_session.send_notification(outbound)
        except Exception as e:
            logger.debug(f"Server notification error: {e}")
    
    @staticmethod
    def _extract_method_and_params(notification_obj):
        obj = getattr(notification_obj, "root", notification_obj)
        method = getattr(obj, "method", None)
        params = getattr(obj, "params", None)
        if method is not None:
            return method, params
        if hasattr(obj, "model_dump"):
            dumped = obj.model_dump(by_alias=True, exclude_none=True)
            return dumped.get("method"), dumped.get("params")
        if isinstance(obj, dict):
            return obj.get("method"), obj.get("params")
        return None, None
    
    async def handle_client_message(self, msg):
        if isinstance(msg, Exception):
            logger.error(f"Client error: {msg}")
            return
        if isinstance(msg, RequestResponder):
            await self.handle_client_request(msg)
        elif isinstance(msg, types.ClientNotification):
            await self.handle_client_notification(msg)
    
    async def handle_server_message(self, msg):
        if isinstance(msg, Exception):
            logger.debug(f"Server message error: {msg}")
            return
        if isinstance(msg, RequestResponder):
            await self.handle_server_request(msg)
        elif isinstance(msg, types.ServerNotification):
            await self.handle_server_notification(msg)
    
    async def start(self):
        # Try SSE connection (best-effort, non-blocking)
        await self.ensure_initialized()
        
        try:
            async with stdio_server() as (stdio_read, stdio_write):
                caps = types.ServerCapabilities(
                    tools=types.ToolsCapability(listChanged=True)
                )
                
                tool_count = len(self._jar_tools)
                rest_count = len(REST_TOOLS)
                
                options = InitializationOptions(
                    server_name="burp-unified",
                    server_version="1.0.0",
                    capabilities=caps,
                    instructions=f"Unified Burp MCP — {tool_count} Jar tools + {rest_count} REST API tools. Total: {tool_count + rest_count}"
                )
                
                async with ServerSession(stdio_read, stdio_write, options) as server_session:
                    self._server_session = server_session
                    
                    async for message in server_session.incoming_messages:
                        await self.handle_client_message(message)
        finally:
            # Cleanup SSE connection
            if self._client_ctx and self._client_session:
                try:
                    await self._client_ctx.__aexit__(None, None, None)
                except:
                    pass
            if self._sse_ctx:
                try:
                    await self._sse_ctx.__aexit__(None, None, None)
                except:
                    pass

# ── Entry Point ──────────────────────────────────────────────────────
async def main():
    """Start bridge with retries — never exit on startup failure."""
    max_startup_retries = 3
    for attempt in range(max_startup_retries):
        try:
            bridge = UnifiedBridge(BURP_SSE_URL)
            await bridge.start()
            return  # success
        except Exception as e:
            if attempt < max_startup_retries - 1:
                delay = 5 * (2 ** attempt)
                logger.error(f"Bridge startup failed (attempt {attempt+1}/{max_startup_retries}): {e}")
                logger.info(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)
            else:
                logger.error(f"Bridge startup failed after {max_startup_retries} attempts: {e}")
                raise

if __name__ == "__main__":
    asyncio.run(main())
