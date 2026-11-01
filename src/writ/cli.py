"""`writ` command line: operator controls and an agent-side harness for testing.

Operator commands need WRIT_GATE_URL and WRIT_ADMIN_TOKEN. Agent commands need WRIT_TASK_TOKEN.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer

from .client import GateAPIError, GateClient
from .ledger import verify_chain
from .signing import Signer
from .templates import TemplateError, load_template, render

app = typer.Typer(help="Writ: execution authority for AI agents.", no_args_is_help=True)
task_app = typer.Typer(help="Task contracts (operator).", no_args_is_help=True)
ledger_app = typer.Typer(help="Hash-chained ledger (operator).", no_args_is_help=True)
auth_app = typer.Typer(help="Authorizations (operator).", no_args_is_help=True)
agent_app = typer.Typer(help="Act as an agent holding a task token (testing).", no_args_is_help=True)
app.add_typer(task_app, name="task")
app.add_typer(ledger_app, name="ledger")
app.add_typer(auth_app, name="auth")
app.add_typer(agent_app, name="agent")


def _out(obj: Any) -> None:
    typer.echo(json.dumps(obj, indent=2, sort_keys=True))


def _admin() -> GateClient:
    url = os.environ.get("WRIT_GATE_URL", "http://localhost:8080")
    tok = os.environ.get("WRIT_ADMIN_TOKEN")
    if not tok:
        typer.echo("WRIT_ADMIN_TOKEN is required", err=True)
        raise typer.Exit(2)
    return GateClient(url, tok)


def _agent() -> GateClient:
    url = os.environ.get("WRIT_GATE_URL", "http://localhost:8080")
    tok = os.environ.get("WRIT_TASK_TOKEN")
    if not tok:
        typer.echo("WRIT_TASK_TOKEN is required", err=True)
        raise typer.Exit(2)
    return GateClient(url, tok)


def _run(fn):
    try:
        return fn()
    except GateAPIError as e:
        typer.echo(f"error {e.status_code} {e.code}: {e.detail}", err=True)
        raise typer.Exit(1) from None
    except httpx.HTTPError as e:
        url = os.environ.get("WRIT_GATE_URL", "http://localhost:8080")
        typer.echo(f"error: cannot reach the gate at {url}: {e.__class__.__name__}: {e}", err=True)
        raise typer.Exit(3) from None


# ---------------------------------------------------------------- keys & setup
@app.command()
def keygen(
    out: Annotated[Path, typer.Option(help="Directory to write key files into")] = Path("deploy/keys"),
) -> None:
    """Generate gate and executor Ed25519 keypairs plus admin/internal tokens."""
    out.mkdir(parents=True, exist_ok=True)
    gate, execr = Signer.generate(), Signer.generate()
    files = {
        "gate.key": gate.encoded_private(),
        "gate.pub": gate.verifier.encoded_public(),
        "executor.key": execr.encoded_private(),
        "executor.pub": execr.verifier.encoded_public(),
        "admin.token": secrets.token_urlsafe(32),
        "internal.token": secrets.token_urlsafe(32),
        "demo_saas.apikey": secrets.token_urlsafe(24),
    }
    for name, val in files.items():
        p = out / name
        p.write_text(val + "\n")
        p.chmod(0o600)
    env = out / "writ.env"
    env.write_text(
        "\n".join(
            [
                f"WRIT_GATE_PRIVATE_KEY={files['gate.key']}",
                f"WRIT_GATE_PUBLIC_KEY={files['gate.pub']}",
                f"WRIT_EXECUTOR_PRIVATE_KEY={files['executor.key']}",
                f"WRIT_EXECUTOR_PUBLIC_KEY={files['executor.pub']}",
                f"WRIT_ADMIN_TOKEN={files['admin.token']}",
                f"WRIT_INTERNAL_TOKEN={files['internal.token']}",
                f"WRIT_DEMO_SAAS_API_KEY={files['demo_saas.apikey']}",
                "",
            ]
        )
    )
    env.chmod(0o600)
    typer.echo(
        f"wrote keys and tokens to {out}/ (gate key id {gate.verifier.key_id}, executor key id {execr.verifier.key_id})"
    )


@app.command()
def status() -> None:
    """Gate status (halted?, version, commands)."""
    _out(_run(lambda: _admin().status()))


@app.command()
def commands() -> None:
    """Show the command table."""
    _out(_run(lambda: _admin().commands()))


@app.command()
def halt(reason: str = "") -> None:
    """Emergency stop: deny every protected action until unhalt."""
    _out(_run(lambda: _admin().halt(reason)))


@app.command()
def unhalt(reason: str = "") -> None:
    _out(_run(lambda: _admin().unhalt(reason)))


@app.command()
def sweep() -> None:
    """Run the gate's maintenance pass now: expire leases, settle orphaned authorizations, auto-reconcile."""
    _out(_run(lambda: _admin().sweep()))


# ---------------------------------------------------------------- tasks
@task_app.command("create")
def task_create(
    template: Annotated[Path | None, typer.Option("--template", "-t", help="Template YAML")] = None,
    grant_file: Annotated[
        Path | None, typer.Option("--grant", "-g", help="Grant JSON file (alternative to template)")
    ] = None,
    param: Annotated[
        list[str] | None, typer.Option("--param", "-p", help="key=value template parameter")
    ] = None,
    name: Annotated[str | None, typer.Option(help="Task name")] = None,
    ttl: Annotated[int | None, typer.Option(help="Lease seconds")] = None,
    max_ttl: Annotated[int | None, typer.Option(help="Hard cap on renewals, seconds")] = None,
    token_only: Annotated[bool, typer.Option(help="Print only the task token")] = False,
) -> None:
    """Create a root task contract from a template or grant file. Prints the task and its token."""
    if (template is None) == (grant_file is None):
        typer.echo("provide exactly one of --template or --grant", err=True)
        raise typer.Exit(2)
    params: dict[str, str] = {}
    for p in param or []:
        if "=" not in p:
            typer.echo(f"bad --param {p!r}; expected key=value", err=True)
            raise typer.Exit(2)
        k, v = p.split("=", 1)
        params[k] = v
    if template is not None:
        try:
            tname, grant, tttl, description, intent = render(load_template(template), params)
        except (TemplateError, ValueError) as e:
            typer.echo(f"template error: {e}", err=True)
            raise typer.Exit(2) from None
        grant_dict = grant.to_dict()
        intent_dict = intent.to_dict() if intent else None
        meta = {"template": str(template), "parameters": params, "description": description}
    else:
        grant_dict = json.loads(grant_file.read_text())
        intent_dict = None
        tname, tttl, meta = grant_file.stem, 3600, {"grant_file": str(grant_file)}
    res = _run(
        lambda: _admin().create_task(
            name or tname, grant_dict, ttl or tttl, max_ttl, meta, intent=intent_dict
        )
    )
    if token_only:
        typer.echo(res["token"])
    else:
        _out(res)


@task_app.command("list")
def task_list(root: str | None = None, status: str | None = None) -> None:
    _out(_run(lambda: _admin().list_tasks(root, status)))


@task_app.command("show")
def task_show(task_id: str) -> None:
    _out(_run(lambda: _admin().get_task(task_id)))


@task_app.command("revoke")
def task_revoke(task_id: str, reason: str = "operator revocation") -> None:
    """Revoke a task and every descendant; void outstanding authorizations."""
    _out(_run(lambda: _admin().revoke(task_id, reason)))


@task_app.command("renew")
def task_renew(task_id: str, seconds: int) -> None:
    """Extend a lease (operator only; capped by max_expires_at and the parent)."""
    _out(_run(lambda: _admin().renew(task_id, seconds)))


@task_app.command("explain")
def task_explain(task_id: str) -> None:
    """Explain the intent state of a task tree: each attempt, what it meant, and the evidence after it."""
    x = _run(lambda: _admin().explain_intent(task_id))
    typer.echo(
        f"mode={x['mode']} e={x['e_value']:.2f} (threshold {x['threshold']:.0f}) forecast={x['forecast']:.3f} (budget {x['risk_budget']})"
    )
    if x["mode_reason"]:
        typer.echo(f"reason: {x['mode_reason']}")
    typer.echo("non-goal mass: " + ", ".join(f"{k}={v:.3f}" for k, v in x["non_goal_mass"].items()))
    for i, h in enumerate(x["history"], 1):
        a = h["action"]
        what = a["command"]
        if a["direct"]:
            what += " direct=" + ",".join(a["direct"])
        if a["requests"]:
            what += " requests=" + ",".join(a["requests"])
        if a["probe"]:
            what += " probe"
        typer.echo(f"{i:>3} {'executed' if h['executed'] else 'denied  '} e={h['e_value']:9.2f}  {what}")


@task_app.command("unsupervise")
def task_unsupervise(task_id: str) -> None:
    """Return a supervised task tree to normal mode after operator review."""
    _out(_run(lambda: _admin().unsupervise(task_id)))


@task_app.command("repin")
def task_repin(task_id: str) -> None:
    """Re-approve a root task against the current integration configuration."""
    _out(_run(lambda: _admin().repin(task_id)))


# ---------------------------------------------------------------- authorizations
@auth_app.command("list")
def auth_list(root: str | None = None, status: str | None = None) -> None:
    _out(_run(lambda: _admin().authorizations(root, status)))


@auth_app.command("show")
def auth_show(auth_id: str) -> None:
    _out(_run(lambda: _admin().get_authorization(auth_id)))


@auth_app.command("approve")
def auth_approve(auth_id: str) -> None:
    """Approve a held authorization: it is signed, dispatched and executed now."""
    _out(_run(lambda: _admin().approve(auth_id)))


@auth_app.command("reject")
def auth_reject(auth_id: str, reason: str = "operator rejected") -> None:
    """Reject a held authorization and release its budget."""
    _out(_run(lambda: _admin().reject(auth_id, reason)))


@auth_app.command("reconcile")
def auth_reconcile(auth_id: str) -> None:
    """Resolve an authorization whose outcome is unknown by asking the executor what happened."""
    _out(_run(lambda: _admin().reconcile(auth_id)))


# ---------------------------------------------------------------- ledger
@ledger_app.command("tail")
def ledger_tail(
    n: Annotated[int, typer.Option("--n", "-n")] = 50, task: str | None = None, root: str | None = None
) -> None:
    entries = _run(lambda: list(_admin().iter_ledger(task_id=task, root_id=root)))
    for e in entries[-n:]:
        p = e["payload"]
        summary = p.get("reason") or p.get("status") or p.get("command") or p.get("name") or ""
        typer.echo(f"{e['seq']:>6} {e['ts'][:19]} {e['type']:<24} {e['task_id'] or '-':<30} {summary}")


@ledger_app.command("export")
def ledger_export(
    out: Path = Path("ledger.jsonl"),
    after: Annotated[
        int, typer.Option(help="Only entries with seq greater than this (incremental export)")
    ] = 0,
) -> None:
    """Export the whole ledger (or the tail after --after) as JSON lines, paging through the gate."""
    n = 0
    with out.open("w") as f:
        for e in _run(lambda: list(_admin().iter_ledger(after=after))):
            f.write(json.dumps(e, sort_keys=True) + "\n")
            n += 1
    typer.echo(f"wrote {n} entries to {out}")


@ledger_app.command("verify")
def ledger_verify(file: Path | None = None) -> None:
    """Verify the hash chain, either on the gate or on an exported file (offline)."""
    if file:
        entries = [json.loads(line) for line in file.read_text().splitlines() if line.strip()]
        ok, err = verify_chain(entries)
        _out({"ok": ok, "entries": len(entries), "error": err})
    else:
        _out(_run(lambda: _admin().ledger_verify()))
    if file and not ok:
        raise typer.Exit(1)


# ---------------------------------------------------------------- agent side
@agent_app.command("me")
def agent_me() -> None:
    _out(_run(lambda: _agent().me()))


@agent_app.command("invoke")
def agent_invoke(
    command: str,
    args: Annotated[str, typer.Argument(help="JSON object")] = "{}",
    idempotency_key: Annotated[
        str | None, typer.Option("--idempotency-key", "-k", help="Replay-safe retry key")
    ] = None,
) -> None:
    """Invoke a command as the agent. Exit 0 when committed or held, 1 when denied or not committed."""
    try:
        parsed = json.loads(args)
    except ValueError as e:
        typer.echo(f"args must be a JSON object: {e}", err=True)
        raise typer.Exit(2) from None
    res = _run(lambda: _agent().invoke(command, parsed, idempotency_key=idempotency_key))
    _out(res)
    if res["decision"] == "denied" or res.get("status") not in ("committed", "held", None):
        raise typer.Exit(1)


@agent_app.command("delegate")
def agent_delegate(
    grant: Annotated[str, typer.Argument(help="Grant JSON (string or @file)")],
    name: str = "sub-agent",
    ttl: int | None = None,
    token_only: bool = False,
) -> None:
    g = json.loads(Path(grant[1:]).read_text()) if grant.startswith("@") else json.loads(grant)
    res = _run(lambda: _agent().delegate(name, g, ttl))
    typer.echo(res["token"]) if token_only else _out(res)


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
