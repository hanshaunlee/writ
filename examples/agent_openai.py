"""Example: an OpenAI-powered agent that works a task through Writ.

Same shape as examples/agent.py, using the OpenAI SDK. The agent has no credentials and no
upstream API access. Its only tools are the commands its task token grants, fetched from the
gate at start-up. Denials come back as tool results so the model can adapt.

    export OPENAI_API_KEY=...
    export WRIT_GATE_URL=http://localhost:8080
    export WRIT_TASK_TOKEN=$(writ task create -t templates/resolve_duplicate_charge.yaml \
        -p customer_id=cus_123 -p billing_contact=ap@acme.example \
        -p max_refund_cents=20000 -p 'charge_ids=["ch_1001","ch_1002"]' --token-only)
    python examples/agent_openai.py "Customer cus_123 says they were charged twice for March. Fix it."
"""

from __future__ import annotations

import json
import os
import sys

from openai import OpenAI

from writ.client import GateAPIError, GateClient

MODEL = os.environ.get("WRIT_EXAMPLE_MODEL", "gpt-5")

SYSTEM = """You are a customer-operations agent. You act only through the tools provided; each tool is a
command checked by an execution authority against the task you were given. A tool may return
decision=denied with a reason: treat that as a hard boundary, explain it, and look for a permitted path.
Never retry a denied action with cosmetic changes. Investigate before acting (read the customer and the
charges), refund only the duplicate, record a note, and notify the billing contact. Finish with a short
summary of what you did and anything you could not do."""


def tool_name(command: str) -> str:
    """OpenAI tool names allow only [a-zA-Z0-9_-]; Writ commands use dots."""
    return command.replace(".", "__")


def command_name(tool: str) -> str:
    return tool.replace("__", ".")


def tools_from_gate(me: dict) -> list[dict]:
    tools = []
    for c in me["commands"]:
        desc = f"[{c['effect_class']}] {c['description']}"
        if c["constraints"]:
            desc += " Constraints on this task: " + json.dumps(c["constraints"])
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool_name(c["name"]),
                    "description": desc,
                    "parameters": c["args_schema"],
                },
            }
        )
    return tools


def run(goal: str) -> None:
    gate = GateClient(os.environ.get("WRIT_GATE_URL", "http://localhost:8080"), os.environ["WRIT_TASK_TOKEN"])
    me = gate.me()
    tools = tools_from_gate(me)
    client = OpenAI()
    messages: list[dict] = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": goal}]
    print(f"task {me['id']} ({me['name']}) expires {me['expires_at']}; {len(tools)} tools; model {MODEL}\n")

    for _ in range(25):
        resp = client.chat.completions.create(model=MODEL, messages=messages, tools=tools)
        msg = resp.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))
        if msg.content and msg.content.strip():
            print(msg.content.strip(), "\n")
        if not msg.tool_calls:
            return
        for call in msg.tool_calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                shown = {"decision": "error", "detail": "tool arguments were not valid JSON"}
            else:
                try:
                    res = gate.invoke(command_name(call.function.name), args)
                except GateAPIError as e:
                    res = {"decision": "error", "code": e.code, "detail": e.detail}
                if res.get("decision") == "denied":
                    shown = {
                        "decision": "denied",
                        "reason": res["denial"]["reason"],
                        "detail": res["denial"]["detail"],
                    }
                else:
                    shown = {
                        "decision": res.get("decision"),
                        "status": res.get("status"),
                        "result": res.get("result"),
                        "error": res.get("error"),
                    }
            print(
                f"  -> {call.function.name}({call.function.arguments}) => {shown.get('reason') or shown.get('status') or shown.get('detail')}"
            )
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(shown)})
    print("stopped: step limit reached")


if __name__ == "__main__":
    run(" ".join(sys.argv[1:]) or "Customer cus_123 reports a duplicate charge for March. Resolve it.")
