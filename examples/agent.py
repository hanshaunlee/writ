"""Example: a Claude agent that works a task through Writ.

The agent has no credentials and no upstream API access. Its only tools are the commands
its task token grants, fetched from the gate at start-up. Denials come back as tool results
so the model can adapt (for example, choose a permitted path) instead of failing silently.

    export ANTHROPIC_API_KEY=...            # or `ant auth login`
    export WRIT_GATE_URL=http://localhost:8080
    export WRIT_TASK_TOKEN=$(writ task create -t templates/resolve_duplicate_charge.yaml \
        -p customer_id=cus_123 -p billing_contact=ap@acme.example \
        -p max_refund_cents=20000 -p 'charge_ids=["ch_1001","ch_1002"]' --token-only)
    python examples/agent.py "Customer cus_123 says they were charged twice for March. Fix it."
"""

from __future__ import annotations

import json
import os
import sys

import anthropic

from writ.client import GateAPIError, GateClient

MODEL = os.environ.get("WRIT_EXAMPLE_MODEL", "claude-opus-5-5")

SYSTEM = """You are a customer-operations agent. You act only through the tools provided; each tool is a
command checked by an execution authority against the task you were given. A tool may return
decision=denied with a reason: treat that as a hard boundary, explain it, and look for a permitted path.
Never retry a denied action with cosmetic changes. Investigate before acting (read the customer and the
charges), refund only the duplicate, record a note, and notify the billing contact. Finish with a short
summary of what you did and anything you could not do."""


def tools_from_gate(me: dict) -> list[dict]:
    tools = []
    for c in me["commands"]:
        desc = f"[{c['effect_class']}] {c['description']}"
        if c["constraints"]:
            desc += " Constraints on this task: " + json.dumps(c["constraints"])
        tools.append({"name": c["name"], "description": desc, "input_schema": c["args_schema"]})
    return tools


def run(goal: str) -> None:
    gate = GateClient(os.environ.get("WRIT_GATE_URL", "http://localhost:8080"), os.environ["WRIT_TASK_TOKEN"])
    me = gate.me()
    tools = tools_from_gate(me)
    client = anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": goal}]
    print(f"task {me['id']} ({me['name']}) expires {me['expires_at']}; {len(tools)} tools\n")

    for _ in range(25):
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=SYSTEM,
            tools=tools,
            messages=messages,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "refusal":
            print("model declined:", response.stop_details and response.stop_details.explanation)
            return
        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(block.text.strip(), "\n")
        if response.stop_reason != "tool_use":
            return
        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            try:
                res = gate.invoke(block.name, block.input)
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
                f"  -> {block.name}({json.dumps(block.input)}) => {shown.get('reason') or shown.get('status')}"
            )
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(shown),
                    "is_error": shown.get("decision") != "allowed",
                }
            )
        messages.append({"role": "user", "content": results})
    print("stopped: step limit reached")


if __name__ == "__main__":
    run(" ".join(sys.argv[1:]) or "Customer cus_123 reports a duplicate charge for March. Resolve it.")
