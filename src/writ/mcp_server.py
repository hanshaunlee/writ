"""MCP server that exposes a task's granted commands as tools.

The agent never sees credentials or upstream APIs; it sees exactly the commands its task
holds, with the task's constraints spelled out in each tool description.  Every call goes
through the gate's invoke pipeline.

    WRIT_GATE_URL=http://gate:8080 WRIT_TASK_TOKEN=wt_... writ-mcp
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .client import GateAPIError, GateClient

DELEGATE_TOOL = "writ_delegate"
STATUS_TOOL = "writ_task_status"


def _describe_constraints(constraints: dict) -> str:
    if not constraints:
        return ""
    parts = []
    for path, ops in constraints.items():
        for op, val in ops.items():
            parts.append(f"{path} {op} {json.dumps(val)}")
    return " Constraints: " + "; ".join(parts) + "."


def build_tools(me: dict) -> list[types.Tool]:
    tools: list[types.Tool] = []
    for c in me["commands"]:
        desc = f"[{c['effect_class']}] {c['description']}{_describe_constraints(c['constraints'])}"
        if c["budgets"]:
            desc += f" Budget charges: {json.dumps(c['budgets'])}."
        tools.append(types.Tool(name=c["name"], description=desc, inputSchema=c["args_schema"]))
    tools.append(
        types.Tool(
            name=STATUS_TOOL,
            description="Show this task's grant, remaining budgets, lease expiry and status.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        )
    )
    tools.append(
        types.Tool(
            name=DELEGATE_TOOL,
            description=(
                "Create a sub-task for a sub-agent with a grant that is a strict subset of this task's grant. "
                "Returns a task token the sub-agent must use. Budgets are shared with this task. "
                "Attempts to widen authority are rejected and recorded."
            ),
            inputSchema={
                "type": "object",
                "required": ["name", "grant"],
                "properties": {
                    "name": {"type": "string"},
                    "grant": {
                        "type": "object",
                        "description": "Grant: {commands:[{command,args:{path:{eq|in|max|min|matches|keys_subset}}}], budgets:{}, forbidden_effects:[]}",
                    },
                    "ttl_seconds": {"type": "integer", "minimum": 1},
                },
                "additionalProperties": False,
            },
        )
    )
    return tools


def _text(obj: Any) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(obj, indent=2, sort_keys=True))]


async def serve(client: GateClient) -> None:
    server = Server("writ")

    async def list_tools(_ctx, _params) -> types.ListToolsResult:
        me = await asyncio.to_thread(client.me)
        return types.ListToolsResult(tools=build_tools(me))

    async def call_tool(_ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name, arguments = params.name, params.arguments or {}
        try:
            if name == STATUS_TOOL:
                me = await asyncio.to_thread(client.me)
                me.pop("commands", None)
                return types.CallToolResult(content=_text(me))
            if name == DELEGATE_TOOL:
                res = await asyncio.to_thread(
                    client.delegate, arguments["name"], arguments["grant"], arguments.get("ttl_seconds")
                )
                return types.CallToolResult(
                    content=_text(
                        {
                            "task_id": res["task"]["id"],
                            "token": res["token"],
                            "grant": res["task"]["grant"],
                            "expires_at": res["task"]["expires_at"],
                        }
                    )
                )
            res = await asyncio.to_thread(client.invoke, name, arguments)
        except GateAPIError as e:
            return types.CallToolResult(
                content=_text({"decision": "error", "code": e.code, "detail": e.detail}), isError=True
            )
        except KeyError as e:
            return types.CallToolResult(
                content=_text({"decision": "error", "detail": f"missing argument {e}"}), isError=True
            )
        if res["decision"] == "denied":
            d = res["denial"]
            body = {"decision": "denied", "reason": d["reason"], "detail": d["detail"]}
            if d.get("extra"):
                body["extra"] = d["extra"]
            return types.CallToolResult(content=_text(body), isError=True)
        out = {
            "decision": "allowed",
            "status": res["status"],
            "result": res["result"],
            "authorization_id": res["authorization_id"],
        }
        if res.get("error"):
            out["error"] = res["error"]
        if res.get("budgets"):
            out["budgets"] = res["budgets"]
        if res["status"] == "held":
            out["note"] = (
                "This action is held for operator review and has not executed. Do not retry it; "
                "continue with other permitted work or stop and report."
            )
        # `held` is a pending outcome, not an error; `failed`/`rejected`/`unknown` are.
        return types.CallToolResult(content=_text(out), isError=res["status"] not in ("committed", "held"))

    server.add_request_handler("tools/list", types.PaginatedRequestParams, list_tools)
    server.add_request_handler("tools/call", types.CallToolRequestParams, call_tool)

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    url = os.environ.get("WRIT_GATE_URL", "http://localhost:8080")
    token = os.environ.get("WRIT_TASK_TOKEN")
    if not token:
        print("WRIT_TASK_TOKEN is required", file=sys.stderr)
        sys.exit(2)
    asyncio.run(serve(GateClient(url, token)))


if __name__ == "__main__":
    main()
