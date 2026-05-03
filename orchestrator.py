"""
Orchestrator Agent - Agent 1
CYB 332 Final Project

Coordinates the full pen-test pipeline:
  scope_validator -> recon_agent -> vuln_analyst -> report_writer

All inter-agent state flows through foundation.SESSION (shared dict).
LangGraph manages node transitions and the out-of-scope guardrail.
Example run prompt: python orchestrator.py [target ip] [target scope/network]
"""

import json
import re
import sys
from typing import Literal

from langgraph.graph import StateGraph, START, END
from langchain.messages import HumanMessage, AIMessage
from typing_extensions import TypedDict, Annotated
import operator
from langchain.messages import AnyMessage

# -- Shared platform -----------------------------------------------------------
from foundation import SESSION, setTarget, logger, saveSes

# -- Teammate agents -----------------------------------------------------------
# agent.py  - recon agent (builds its own graph; we invoke it via run_recon)
# vuln_agent.py - run_vulnerability_agent(recon_text) -> JSON str
# ReportWriter.py - runWriter() reads SESSION and writes SESSION["finalReport"]
from vuln_agent import run_vulnerability_agent
from ReportWriter import runWriter


# -----------------------------------------------------------------------------
# 1.  ORCHESTRATOR STATE
#     Keeps a running message log so the graph has something to pass around,
#     plus lightweight status flags the conditional edge needs.
# -----------------------------------------------------------------------------

class OrchestratorState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]   # running log
    target_ip: str
    scope: str          # e.g. "192.168.50.0/24"
    scope_valid: bool
    current_phase: str  # init | recon | vuln | report | done | halted | failed
    errors: list[str]


# -----------------------------------------------------------------------------
# 2.  SCOPE HELPER
#     Checks the target IP against the allowed CIDR / IP list.
#     Supports exact-IP match or the last-octet wildcard implied by a /24.
# -----------------------------------------------------------------------------

def _ip_in_scope(ip: str, scope: str) -> bool:
    """
    Returns True when `ip` is covered by `scope`.
    Handles:
      * exact match          192.168.50.10  == 192.168.50.10
      * /24 CIDR prefix      192.168.50.10  in 192.168.50.0/24
      * comma-separated list 192.168.50.10, 10.0.0.5
    """
    ip = ip.strip()
    for entry in scope.split(","):
        entry = entry.strip()
        if entry == ip:
            return True
        if "/" in entry:
            # naive prefix match - good enough for /8 /16 /24
            prefix = entry.split("/")[0].rsplit(".", 1)[0]   # e.g. "192.168.50"
            bits = int(entry.split("/")[1])
            octets = bits // 8
            ip_prefix = ".".join(ip.split(".")[:octets])
            scope_prefix = ".".join(entry.split("/")[0].split(".")[:octets])
            if ip_prefix == scope_prefix:
                return True
    return False


# -----------------------------------------------------------------------------
# 3.  NODE - SCOPE VALIDATOR  (guardrail)
# -----------------------------------------------------------------------------

def scope_validator(state: OrchestratorState) -> OrchestratorState:
    """
    Guardrail node.  Sets scope_valid=False and halts the graph if the target
    IP is outside the declared scope string.  Also initialises foundation.SESSION
    via setTarget() so all downstream agents share the same target context.
    """
    target = state["target_ip"]
    scope  = state["scope"]

    logger("Orchestrator", "scope_check", {"target": target, "scope": scope})

    if not _ip_in_scope(target, scope):
        msg = f"[GUARDRAIL] Target {target!r} is OUTSIDE scope {scope!r}. Halting."
        logger("Orchestrator", "scope_rejected", {"reason": msg})
        print(f"\n-  {msg}\n")
        return {
            **state,
            "scope_valid": False,
            "current_phase": "halted",
            "errors": state.get("errors", []) + [msg],
            "messages": state["messages"] + [
                AIMessage(content=msg, name="Orchestrator")
            ],
        }

    # Initialize the shared session used by all teammate agents
    setTarget(target, scope)
    logger("Orchestrator", "scope_accepted", {"target": target})
    print(f"\nSUCCESS  Target {target!r} accepted (scope: {scope})\n")

    return {
        **state,
        "scope_valid": True,
        "current_phase": "recon",
        "messages": state["messages"] + [
            AIMessage(
                content=f"Scope validated. Target: {target}",
                name="Orchestrator",
            )
        ],
    }


# -----------------------------------------------------------------------------
# 4.  NODE - RECON AGENT  (wraps agent.py)
# -----------------------------------------------------------------------------

def recon_node(state: OrchestratorState) -> OrchestratorState:
    """
    Invokes the recon agent (agent.py).

    agent.py builds and compiles its LangGraph internally and runs a single
    fixed query at module-import time.  To integrate cleanly without rewriting
    your teammate's file we:
      1. Import the compiled `agent` graph.
      2. Send a targeted HumanMessage for the specific target IP.
      3. Extract the final AI message as the recon summary.
      4. Persist structured results to SESSION["recon"].
    """
    print("\n[2/4] Recon Agent - starting...\n")
    logger("Orchestrator", "dispatch_recon", {"target": state["target_ip"]})

    try:
        # Import here (not top-level) so agent.py's module-level invoke
        # doesn't fire before the scope check.
        from agent import agent as recon_agent  # the compiled LangGraph agent

        target = state["target_ip"]
        query = (
            f"Perform a full reconnaissance scan of {target}. "
            "Run an nmap port scan to identify open ports, services, and OS. "
            "Return all findings as structured text with port numbers, service names, "
            "and version strings."
        )

        result = recon_agent.invoke({
            "messages": [HumanMessage(content=query)],
            "llm_calls": 0,
        })

        # Extract the last AI message as recon text
        recon_text = ""
        for msg in reversed(result["messages"]):
            if isinstance(msg, AIMessage) and msg.content:
                recon_text = (
                    msg.content
                    if isinstance(msg.content, str)
                    else str(msg.content)
                )
                break

        # Persist to shared SESSION so downstream agents can read it
        SESSION["recon"] = {
            "target": target,
            "raw_output": recon_text,
        }
        saveSes()

        logger("Orchestrator", "recon_complete",
               {"chars": len(recon_text)})
        print(f"\nSUCCESS  Recon complete ({len(recon_text)} chars)\n")

        return {
            **state,
            "current_phase": "vuln",
            "messages": state["messages"] + [
                AIMessage(content=recon_text, name="ReconAgent")
            ],
        }

    except Exception as exc:
        err = f"Recon agent failed: {exc}"
        logger("Orchestrator", "recon_error", {"error": err})
        print(f"\nFAILURE  {err}\n")
        return {
            **state,
            "current_phase": "failed",
            "errors": state.get("errors", []) + [err],
            "messages": state["messages"] + [
                AIMessage(content=err, name="Orchestrator")
            ],
        }


# -----------------------------------------------------------------------------
# 5.  NODE - VULNERABILITY ANALYST  (wraps vuln_agent.py)
# -----------------------------------------------------------------------------

def vuln_analyst_node(state: OrchestratorState) -> OrchestratorState:
    """
    Passes recon output to run_vulnerability_agent() and stores the parsed
    JSON result in SESSION["vulnAnly"] so the ReportWriter can consume it.
    """
    print("\n[3/4] Vulnerability Analyst - starting...\n")
    logger("Orchestrator", "dispatch_vuln_analyst", {})

    try:
        # Pull recon text from SESSION (set by recon_node)
        recon_data = SESSION.get("recon", {})
        recon_text = recon_data.get("raw_output", "")

        if not recon_text:
            raise ValueError("No recon output found in SESSION['recon'].")

        vuln_json_str = run_vulnerability_agent(recon_text)

        # Parse and validate the JSON the vuln agent returned
        try:
            vuln_data = json.loads(vuln_json_str)
        except json.JSONDecodeError:
            # Strip markdown fences if the model wrapped the JSON
            clean = re.sub(r"```(?:json)?", "", vuln_json_str).strip()
            start, end = clean.find("{"), clean.rfind("}") + 1
            vuln_data = json.loads(clean[start:end])

        SESSION["vulnAnly"] = vuln_data
        saveSes()

        logger("Orchestrator", "vuln_complete",
               {"findings": len(vuln_data.get("vulnerabilities", []))})
        print(f"\nSUCCESS  Vuln analysis complete "
              f"({len(vuln_data.get('vulnerabilities', []))} findings)\n")

        return {
            **state,
            "current_phase": "report",
            "messages": state["messages"] + [
                AIMessage(content=vuln_json_str, name="VulnAnalyst")
            ],
        }

    except Exception as exc:
        err = f"Vulnerability analyst failed: {exc}"
        logger("Orchestrator", "vuln_error", {"error": err})
        print(f"\nFAILURE  {err}\n")
        return {
            **state,
            "current_phase": "failed",
            "errors": state.get("errors", []) + [err],
            "messages": state["messages"] + [
                AIMessage(content=err, name="Orchestrator")
            ],
        }


# -----------------------------------------------------------------------------
# 6.  NODE - REPORT WRITER  (wraps ReportWriter.py)
# -----------------------------------------------------------------------------

def report_writer_node(state: OrchestratorState) -> OrchestratorState:
    """
    Calls runWriter() from ReportWriter.py.
    runWriter() reads SESSION["recon"] and SESSION["vulnAnly"] directly,
    invokes the report-writer LangGraph agent, and writes:
      * SESSION["finalReport"]   - parsed report dict
      * output/report_<id>.md   - formatted markdown file
    """
    print("\n[4/4] Report Writer - generating final report...\n")
    logger("Orchestrator", "dispatch_report_writer", {})

    try:
        report_data = runWriter()   # reads SESSION, writes back to SESSION

        summary = report_data.get("summary", "Report generated successfully.")
        logger("Orchestrator", "report_complete",
               {"findings": len(report_data.get("findings", []))})
        print(f"\nSUCCESS  Report complete.\n")

        return {
            **state,
            "current_phase": "done",
            "messages": state["messages"] + [
                AIMessage(content=summary, name="ReportWriter")
            ],
        }

    except Exception as exc:
        err = f"Report writer failed: {exc}"
        logger("Orchestrator", "report_error", {"error": err})
        print(f"\nFAILURE  {err}\n")
        return {
            **state,
            "current_phase": "failed",
            "errors": state.get("errors", []) + [err],
            "messages": state["messages"] + [
                AIMessage(content=err, name="Orchestrator")
            ],
        }


# -----------------------------------------------------------------------------
# 7.  CONDITIONAL EDGES
# -----------------------------------------------------------------------------

def after_scope_check(state: OrchestratorState) -> Literal["recon", "__end__"]:
    """Route to recon if in-scope, otherwise terminate."""
    return "recon" if state["scope_valid"] else END


def after_recon(state: OrchestratorState) -> Literal["vuln_analyst", "__end__"]:
    """Continue to vuln analysis unless recon failed."""
    return "vuln_analyst" if state["current_phase"] == "vuln" else END


def after_vuln(state: OrchestratorState) -> Literal["report_writer", "__end__"]:
    """Continue to report writer unless vuln analysis failed."""
    return "report_writer" if state["current_phase"] == "report" else END


# -----------------------------------------------------------------------------
# 8.  BUILD & COMPILE THE GRAPH
# -----------------------------------------------------------------------------

def build_orchestrator():
    graph = StateGraph(OrchestratorState)

    graph.add_node("scope_validator",  scope_validator)
    graph.add_node("recon",            recon_node)
    graph.add_node("vuln_analyst",     vuln_analyst_node)
    graph.add_node("report_writer",    report_writer_node)

    graph.set_entry_point("scope_validator")

    # Guardrail edge - halts immediately if out of scope
    graph.add_conditional_edges(
        "scope_validator",
        after_scope_check,
        {"recon": "recon", END: END},
    )

    # Error-aware edges for the remaining pipeline stages
    graph.add_conditional_edges(
        "recon",
        after_recon,
        {"vuln_analyst": "vuln_analyst", END: END},
    )
    graph.add_conditional_edges(
        "vuln_analyst",
        after_vuln,
        {"report_writer": "report_writer", END: END},
    )

    graph.add_edge("report_writer", END)

    return graph.compile()


# -----------------------------------------------------------------------------
# 9.  PUBLIC ENTRY POINT
# -----------------------------------------------------------------------------

def run_pentest(target_ip: str, scope: str) -> dict:
    """
    Main entry point.  Call this from the command line or import it.

    Parameters
    ----------
    target_ip : str   e.g. "192.168.50.10"
    scope     : str   e.g. "192.168.50.0/24"  or  "192.168.50.10, 192.168.50.11"

    Returns
    -------
    dict  - the final OrchestratorState after the graph completes.
    """
    orchestrator = build_orchestrator()

    initial_state: OrchestratorState = {
        "messages":     [HumanMessage(content=f"Begin pen-test against {target_ip}")],
        "target_ip":    target_ip,
        "scope":        scope,
        "scope_valid":  False,
        "current_phase": "init",
        "errors":       [],
    }

    print(f"\n{'='*60}")
    print(f"  CYB-332 Multi-Agent Pen-Test Tool")
    print(f"  Target : {target_ip}")
    print(f"  Scope  : {scope}")
    print(f"  Session: {SESSION['sessionID']}")
    print(f"{'='*60}\n")

    final_state = orchestrator.invoke(initial_state)

    # -- Summary ---------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"  Phase  : {final_state['current_phase'].upper()}")

    if final_state["errors"]:
        print("\n  Errors encountered:")
        for e in final_state["errors"]:
            print(f"    * {e}")

    report = SESSION.get("finalReport", {})
    if report:
        rs = report.get("riskSum", {})
        print(f"\n  Risk summary : {rs}")
        session_path = saveSes()
        print(f"  Session saved: {session_path}")

    print(f"{'='*60}\n")

    return final_state


# -----------------------------------------------------------------------------
# 10.  CLI
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Usage:  python orchestrator.py <target_ip> [scope]
    # Example: python orchestrator.py 192.168.50.10 192.168.50.0/24

    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <target_ip> [scope_cidr]")
        print("Example: python orchestrator.py 192.168.50.10 192.168.50.0/24")
        sys.exit(1)

    target = sys.argv[1]
    scope  = sys.argv[2] if len(sys.argv) > 2 else "192.168.50.0/24"

    run_pentest(target, scope)
