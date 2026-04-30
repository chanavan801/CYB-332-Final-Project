"""
This program is meant to take the results provided 
from other agents and generate a report on any findings.

CYB 332 Final Project
Agent 4
"""

import json
import time
import operator
from pathlib import Path
from typing_extensions import TypedDict, Annotated

from langgraph.graph import StateGraph, START, END
from langchain.chat_models import init_chat_model
from langchain.messages import AnyMessage, HumanMessage, SystemMessage, AIMessage
from foundation import SESSION, TargetedIP, logger, saveSes
model = init_chat_model("claude-sonnet-4-6", temperature=0)


class agentState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    llm_calls: int
    agent_name: str

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

    "riskSummary": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0},
    "conclusion": "<2-3 sentence overall security posture>"

}
"""

def llm_call(state: agentState):
    logger("ReportWriter", llm_call, {"call": state.get("llm_calls", 0) + 1})
    response= model.invoke([SystemMessage(content=REPORT_WRITER_PROMPT)] + state["messages"])
    return {"messages": [response], "llm_calls": state.get("llm_calls", 0) + 1, "agent_name": "ReportWriter"}


#building agent not sure if this works? tried to write everything in my code based on 
#agent.py

_builder = StateGraph(agentState)
_builder.add_node("llm_call", llm_call)
_builder.add_edge(START, "llm_call")
_builder.add_edge("llm_call", END)

reportAgent =_builder.compile()


#Helper for JSON

def _parse_json(text: str) -> dict:
    clean = text.strip()
    if clean.startswith("'''"):
        parts = clean.split("'''")
        clean = parts[1] if len(parts) > 1 else clean
        if clean.startswith("json"):
            clean = clean[4:]
            return json.loads(clean.strip())
        
        
def saveReport(report: dict) -> str:
    rs= report.get("riskSum",{})
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

    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        lines.append(f"| {sev} | {rs.get(sev, 0)} |")
        lines.append("\n## Findings\n")
        for f in report.get("findings", []):
            lines += [
                f"### {f.get('id', '')} - {f.get('title', '')} **[{f.get('severity', '')}]**\n",
                f"**Affected:** '{f.get('affectedComponent', '')}'\n",
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
        


def runWriter() -> dict:
    """
    Reads SESSION['recon'] and SESSION['vulnerability_analysis'],
    invokes the ReportWriter agent, and writes results back to SESSION.
    Returns the parsed report dict.
    """
    reconData = SESSION.get("recon", {})
    vulnData = SESSION.get("vulnAnly", {})

    if not reconData: 
        raise ValueError("[ReportWriter] No recon data in SESSION.")
    if not vulnData:
        raise ValueError("[ReportWriter] No vulnerability analysis in SESSION.")
    
    print("\n[4/4] ReportWriter - generating final report...")

    result = reportAgent.invoke({
        "messages": [HumanMessage(content=(
            f"Write the full pen-test report for target {TargetedIP}.\n\n"
            f"RECON FINDINGS:\n{json.dumps(reconData, indent=2)}\n\n"
            f"VULNERABILITY ANALYSIS:\n{json.dumps(vulnData, indent=2)}"
        ))],
        "llm_calls":  0,
        "agent_name": "ReportWriter",
    })


    # Extract text from last AI message
    # need to test stuff 
    reportCont = ""
    for msg in reversed(result["messages"]):
        if isinstance(msg, AIMessage) and msg.content:
            reportCont = msg.content if isinstance(msg.content, str) else str(msg.content)
            break

    try: 
     reportData = _parse_json(reportCont)
    except Exception:
        print("[ERROR] ReportWriter returned invalid JSON. Raw output: \n", reportCont)
        raise

    SESSION["finalReport"] = reportData
    saveSes()

    mdPath = saveReport(reportData)
    print(f" Report saved to {mdPath}")
    # not sure if I'm printing things right?

    return reportData


            


