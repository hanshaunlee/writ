import json

from writ.mcp_server import DELEGATE_TOOL, STATUS_TOOL, build_tools


def test_mcp_tools_reflect_grant(h):
    _, tok = h.create_scenario_task()
    me = h.agent(tok).me()
    tools = build_tools(me)
    names = [t.name for t in tools]
    assert names[-2:] == [STATUS_TOOL, DELEGATE_TOOL]
    assert set(names[:-2]) == {c["name"] for c in me["commands"]}
    refund = next(t for t in tools if t.name == "billing.refund")
    assert refund.input_schema["additionalProperties"] is False
    assert "amount_cents max 20000" in refund.description and "ch_1001" in refund.description
    # Tool schema is JSON-serialisable for MCP clients.
    json.dumps([t.model_dump(by_alias=True) for t in tools])
