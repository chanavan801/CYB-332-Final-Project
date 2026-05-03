"""
This program is meant to take the results provided 
from other agents and generate a report on any findings.

CYB 332 Final Project
Agent 4
"""

# Langchain imports
from langchain.chat_models import init_chat_model
from langchain.messages import AnyMessage, HumanMessage, SystemMessage, AIMessage


#State imports
import operator
from typing_extensions import TypedDict, Annotated


#Logic imports
from langgraph.graph import StateGraph, START, END


#Library imports
import json
import time
from pathlib import Path


#import helper file 
from foundation import SESSION, targetedIP, logger, saveSes

#-----------------------------------------------------------------------------------

#Load the model
model = init_chat_model("claude-sonnet-4-6", temperature=0)

#Setup the model
class agentState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    llm_calls: int
    agent_name: str


#replace and fix things as needed!! Some things might need to be changed to work with
#agent.py

#------------------------------------------------------------------------------------

#System prompt below for the report

REPORT_WRITER_PROMPT = """
You're a professional penetration test report writer.
You will receive reconnaissance and a vulnerability analysis.
Write a structured and professional penetration test report.

ONLY reference services, ports, and vulnerabilities that appear in the data provided to you by the recieved reconnissance and vulnerability analysis.
Do NOT invent CVEs, exploits, or vulnerabilities that are not in the input.
Do NOT add findings that were not identified by the vulnerability analysis agent or the reconnaissance agent.


Respond with ONLY a JSON object.
Do NOT include any text before or after the JSON.

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
            "severity": "Critical|High|Medium|Low",
            "affectedComponent": "<service:port>",
            "description": "<technical detail>",
            "evidence": "<observed output>",
            "remediation": "<specific fix>",
            "references": ["<CVE or URL>"]
        }
    ],

    "riskSum": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
    "conclusion": "<2-3 sentence overall security posture>"

}
"""
#------------------------------------------------------------------------------------
# LLM Node
def llm_call(state: agentState):

    logger(
        "ReportWriter", "llm_call", {
            "call": state.get("llm_calls", 0) + 1
            })
    
    
    response= model.invoke(
        [SystemMessage(
            content=REPORT_WRITER_PROMPT
            )] + state["messages"]
         )
    
    
    return {
        "messages": [response], "llm_calls": state.get(
                "llm_calls", 0) + 1, "agent_name": "ReportWriter"
            
                }


#building agent not sure if this works? tried to write everything in my code based on 
#agent.py

#building graph

_builder = StateGraph(agentState)
_builder.add_node("llm_call", llm_call)
_builder.add_edge(START, "llm_call")
_builder.add_edge("llm_call", END)

reportAgent =_builder.compile()


#Helper for JSON

def _parse_json(text: str) -> dict:
    # handle if text came in as a list
    if isinstance(text, list):
        text = " ".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in text])
    

    clean = text.strip()
    if not clean:
        raise ValueError("Empty response from LLM")
    

    # strip markdown fences
    # when I tried to have it not do that in the prompt, it didn't always work.
    #instead of trying to get that prompt to work, I decided it will be better to add code to get rid
    #of the markdown fence things instead. Better to guarnentee it then hope the prompt will listen. 
    if "```" in clean:
        parts = clean.split("```")
        for part in parts:
            if part.startswith("json"):
                clean = part[4:]
                break
            elif part.strip().startswith("{"):
                clean = part
                break
    

    # find the JSON object
    start = clean.find("{")
    end = clean.rfind("}") + 1
    if start != -1 and end > start:
        clean = clean[start:end]
    
    return json.loads(clean.strip())


#Formats the file and makes it readable
# using f-strings to help make this easier. I'm pretty sure its meant to make things more readable.
# This can be double checked
    
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

    for sev in ["Critical", "High", "Medium", "Low"]:
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
            

            lines += [
                "## Conclusion\n", report.get("conclusion", "") + "\n"
                ]


            Path("output").mkdir(exist_ok=True)
            path = f"output/report_{SESSION['sessionID']}.md"
            with open(path, "w") as fh:
                fh.write("\n".join(lines))
            return path
        

#may need to be checked/adjusted again later
def runWriter() -> dict:
    """
    Reads session output from the recon agent and from the vulnerability analysis agent,
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
            f"Write the full pen-test report for target {targetedIP}.\n\n"
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


    #tester code to debug reportcont 
    print("DEBUG raw output:", repr(reportCont))
    print("DEBUG last message type:", type(result["messages"][-1]))
    print("DEBUG last message content:", result["messages"][-1].content)    


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

#-------------------------------------------------------------------------------

#code to test the functionality of the report generation.
# I'm not sure if this is allowed to stay in or if we can comment it out for the final version?
# tested it and it does work. 
if __name__ == "__main__":
    from foundation import SESSION, setTarget
    

    # fake data so ReportWriter has something to work with
    setTarget("192.168.50.10", "192.168.50.0/24")
    SESSION["recon"] = {
        "target": "192.168.50.10",
        "live_hosts": ["192.168.50.10"],
        "open_ports": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 4.7"},
            {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.2.8"}

     ],
        "os_guess": "Linux 2.6.x"
    }


    SESSION["vulnAnly"] = {
        "target": "192.168.50.10",
        "vulnerabilities": [
            {
                "service": "ftp",
                "port": 21,
                "risk": "Critical",
                "reason": "vsftpd 2.3.4 has a known backdoor",
                "exploit": "CVE-2011-2523",
                "evidence": "vsftpd 2.3.4 detected on port 21"
            }
        ],
        
        "overall_assessment": "System is critically vulnerable."
    }
    
    result = runWriter()
    print(json.dumps(result, indent=2))
