from typing_extensions import TypedDict, Annotated
import operator

from langgraph.graph import StateGraph, START, END
from langchain.chat_models import init_chat_model
from langchain.messages import HumanMessage, SystemMessage, AnyMessage


# 1. Load LLM (Claude)

model = init_chat_model(
    "claude-sonnet-4-6",
    temperature=0
)

# 2. Define state 

class AgentState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    llm_calls: int


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

def llm_call(state: dict):
    response = model.invoke(
        [
            SystemMessage(content=SYSTEM_PROMPT)
        ]
        + state["messages"]
    )

    return {
        "messages": [response],
        "llm_calls": state.get("llm_calls", 0) + 1
    }


# 5. BUILD GRAPH 

builder = StateGraph(AgentState)

builder.add_node("llm_call", llm_call)

builder.add_edge(START, "llm_call")
builder.add_edge("llm_call", END)

vuln_agent = builder.compile()


# 6. RUN FUNCTION 

def run_vulnerability_agent(recon_text: str):

    result = vuln_agent.invoke({
        "messages": [
            HumanMessage(content=recon_text)
        ],
        "llm_calls": 0
    })

    return result["messages"][-1].content
