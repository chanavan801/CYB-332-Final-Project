"""
agent 3
vulnerability analyst
CYB 332 Final Project
"""

import operator
from typing_extensions import TypedDict, Annotated

from langgraph.graph import StateGraph, START, END
from langchain.chat_models import init_chat_model
from langchain.messages import HumanMessage, SystemMessage, AnyMessage, AIMessage

import os

#import helper file 
from foundation import SESSION, targetedIP, logger, saveSes


# 1. LOAD MODEL 

model = init_chat_model(
    "claude-sonnet-4-6",
    temperature=0
)



# 2. DEFINE STATE


class AgentState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    llm_calls: int
    agent_name: str


# 3. SYSTEM PROMPT


SYSTEM_PROMPT = """
You are a vulnerability analyst.

Your job is to analyze network scan results and identify security vulnerabilities.

Rules:
- Only use provided data
- Do NOT hallucinate services
- Be conservative in severity
- Output ONLY valid JSON

Output format:

{
  "target": "ip address",
  "vulnerabilities": [
    {
      "service": "",
      "port": 0,
      "risk": "",
      "reason": "",
      "exploit": "",
      "evidence": ""
    }
  ],
  "overall_assessment": ""
}
"""


# 4. LLM NODE


def llm_call(state: AgentState):
    """LLM call node"""

    response = model.invoke(
        [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]
    )

    return {
        "messages": [response],
        "llm_calls": state.get("llm_calls", 0) + 1,
        "agent_name": "VulnerabilityAnalyst",
    }



# 5. BUILD GRAPH


_builder = StateGraph(AgentState)

_builder.add_node("llm_call", llm_call)

_builder.add_edge(START, "llm_call")
_builder.add_edge("llm_call", END)

vuln_agent = _builder.compile()



# 6. HELPER: EXTRACT OUTPUT


def _get_last_ai_message(messages):
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            return msg.content if isinstance(msg.content, str) else str(msg.content)
    return ""

# 7. RUN FUNCTION

def run_vulnerability_agent(recon_text: str) -> str:
    """Runs the vulnerability analysis agent"""

    if not recon_text:
        raise ValueError("No reconnaissance output was provided to Agent 3.")

    result = vuln_agent.invoke({
        "messages": [HumanMessage(content=recon_text)],
        "llm_calls": 0,
        "agent_name": "VulnerabilityAnalyst",
    })

    return _get_last_ai_message(result["messages"])
