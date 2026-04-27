"""
agent 4
report writer
CYB 332 Final Project

"""

#not sure if the line below is correct?? tried to get a rough idea
from agent import SESSION, log_event, save_session, TARGET_IP, AgentState, model
import json
import time
import operator
from pathlib import Path
from typing import Literal
from typing_extensions import TypedDict, Annotated

from langchain.chat_models import init_chat_model
from langchain.messages import AnyMessage, HumanMessage, SystemMessage, AIMessage
from langgraph.graph import StateGraph, START, END


#replace and fix things as needed!! Some things might need to be changed to work with
#agent.py

REPORT_WRITER_PROMPT = """
You're a professional penetration test report writer.
You will receive reconnaissance and a vulnerability analysis.
Write a structured and professional penetration test report.

Respond with ONLY a JSON object:

{

    "reportTitle": "Penetration Test Report",
    "date": "<YYYY-MM-DD>",
    "target": "<ip>",
    "summary": "<3-5 sentence non-technical summary>",
    "scope": "<what was tested>",
    "methodology": "<brief apporach description>",
    "findings": [
        {
            "id": "FIND-001"
            "title": "<short title>",
            "severity": "Critical|High|Medium|Low|Informational",
            "affectedComponent": "<service:port>",
            "description": "<technical detail>",
            "evidence": "<observed output>",
            "remediation": "<specific fix>",
            "references": ["<CVE or URL>"]
        }
    ],

    "riskSummary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
    "conclusion": "<2-3 sentence overall security posture>"

}
"""

#langgraph stuff

def llm_call(state: AgentState):
    """LLM call node - no tools needed for report writing."""
    log_event("ReportWriter", "llm_call", {"call number": state.get("llm_calls", 0) + 1})
    response = model.invoke([SystemMessage(content=REPORT_WRITER_PROMPT)] + state["messages"])
    log_event("ReportWriter", "llm_response", {"finish_reason": "stop"})
    return {
        "messages": [response],
        "llm_calls": state.get("llm_calls", 0) + 1,
        "agent_name": "ReportWriter",
    }


#building agent not sure if this works? tried to write everything in my code based on 
#agent.py

_builder = StateGraph(AgentState)
_builder.add_node("llm_call", llm_call)
_builder.add_edge(START, "llm_call")
_builder.add_edge("llm_call", END)

report_agent =_builder.compile()


#Helper for JSON

def _parse_json(text: str) -> dict:
    clean = text.strip()
    if clean.startswith("'''"):
        parts = clean.split("'''")
        clean = parts[1] if len(parts) > 1 else clean
        if clean.startswith("json"):
            clean = clean[4:]
            return json.loads(clean.strip().rstrip("'").strip())
        


#save markdown report

def save_markdown_report(report: dict) -> str:
    lines = [
        f"# {report.get('reportTitle', 'Penetration Test Report')}",
        f"\n**Date:** {report.get('date', time.strftime('%Y-%m-%d'))}",
        "---\n", 
        "## Executive Summary\n",
        report.get("summary", "") + "\n",
        "## Scope\n",
        report.get("scope", "") + "\n",
        "## Methodology\n", 
        report.get("methodology", "") + "\n",
        "## Risk Summary\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    rs = report.get("riskSummary", {})
    for sev in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {sev} | {rs.get(sev, 0)} |")
        lines.append("\n## Findings\n")
        for f in report.get("findings", []):
            lines += [
                f"### {f.get('id', '')} - {f.get('title', '')} **[{f.get('severity', '')}]**\n",
                f"**Affected:** '{f.get('affected_component', '')}'\n",
                f"**Description:** {f.get('description', '')}\n",
                f"**Evidence:**\n'''\n{f.get('evidence','')}\n'''\n",
                f"**Remediation:** {f.get('remediation', '')}\n",

            ]
            if f.get("references"):
                lines.append(f"**References:** {', '.join(f['references'])}\n")
            lines.append("---\n")
            lines += ["## Conclusion\n", report.get("conclusion", "") + "\n"]

            Path("output").mkdir(exist_ok=True)
            path = f"output/report_{SESSION['session_id']}.md"
            with open(path, "w") as fh:
                fh.write("\n".join(lines))
            return path
        


def run_report_writer() -> dict:
    """
    Reads SESSION['recon'] and SESSION['vulnerability_analysis'],
    invokes the ReportWriter agent, and writes results back to SESSION.
    Returns the parsed report dict.
    """
    recon_data = SESSION.get("recon", {})
    vuln_data = SESSION.get("vulnerability_analysis", {})

    if not recon_data: 
        raise ValueError("[ReportWriter] No recon data in SESSION.")
    if not vuln_data:
        raise ValueError("[ReportWriter] No vulnerability analysis in SESSION.")
    
    print("\n[4/4] ReportWriter - generating final report...")

    result = report_agent.invoke({
        "messages": [HumanMessage(content=(
            f"Write the full pen-test report for target {TARGET_IP}.\n\n"
            f"RECON FINDINGS:\n{json.dumps(recon_data, indent=2)}\n\n"
            f"VULNERABILITY ANALYSIS:\n{json.dumps(vuln_data, indent=2)}"
        ))],
        "llm_calls":  0,
        "agent_name": "ReportWriter",
    })


    # Extract text from last AI message
    # need to test stuff 
    report_text = ""
    for msg in reversed(result["messages"]):
        if isinstance(msg, AIMessage) and msg.content:
            report_text = msg.content if isinstance(msg.content, str) else str(msg.content)
            break

    try: 
     report_data = _parse_json(report_text)
    except Exception:
        print("[ERROR] ReportWriter returned invalid JSON. Raw output: \n", report_text)
        raise

    SESSION["final_report"] = report_data
    save_session()

    md_path = save_markdown_report(report_data)
    print(f" Report saved to {md_path}")
    # not sure if I'm printing things right?

    return report_data


            


