# Install required packages if not already installed
import subprocess
subprocess.run(["pip", "install", "-U", "langchain-anthropic", "langchain-core", "langgraph", "langchain", "IPython"])
from langchain.tools import tool
from langchain.chat_models import init_chat_model
import os

#State imports
from langchain.messages import AnyMessage
from typing_extensions import TypedDict, Annotated
import operator

#Model nodes imports
from langchain.messages import SystemMessage

#Tool node imports
from langchain.messages import ToolMessage

#Logic imports
from typing import Literal
from langgraph.graph import StateGraph, START, END

#import helper file 
from foundation import SESSION, targetedIP, logger, saveSes



model = init_chat_model(
    "claude-sonnet-4-6",
    temperature=0
)


# Step 1: Define tools
@tool
def execute_shell_command(command: str):
    """Executes a given shell command and returns the output."""
    try:
        # Avoid shell=True for security unless necessary
        result = subprocess.run(command.split(), capture_output=True, text=True, timeout=30)
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}
    except Exception as e:
        return f"Error: {str(e)}"

# Augment the LLM with tools
tools = [execute_shell_command]
tools_by_name = {tool.name: tool for tool in tools}
model_with_tools = model.bind_tools(tools)

# Step 2: Define state
class MessagesState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    llm_calls: int

# Step 3: Define model node
def llm_call(state: dict):
    """LLM decides whether to call a tool or not"""

    return {
        "messages": [
            model_with_tools.invoke(
                [
                    SystemMessage(
                        content="You are a helpful assistant tasked with assisting in reconnaissance pentesting. You are under strict orders not to run scans, interfere with, or otherwise affect any system outside of the 192.168.50.0/24 address range. If you realize you are doing so, immediately cease all activity"
                    )
                ]
                + state["messages"]
            )
        ],
        "llm_calls": state.get('llm_calls', 0) + 1
    }


# Step 4: Define tool node
def tool_node(state: dict):
    """Performs the tool call"""

    result = []
    for tool_call in state["messages"][-1].tool_calls:
        tool = tools_by_name[tool_call["name"]]
        observation = tool.invoke(tool_call["args"])
        result.append(ToolMessage(content=observation, tool_call_id=tool_call["id"]))
    return {"messages": result}

# Step 5: Define logic to determine whether to end
# Conditional edge function to route to the tool node or end based upon whether the LLM made a tool call
def should_continue(state: MessagesState) -> Literal["tool_node", END]:
    """Decide if we should continue the loop or stop based upon whether the LLM made a tool call"""

    messages = state["messages"]
    last_message = messages[-1]

    # If the LLM makes a tool call, then perform an action
    if last_message.tool_calls:
        return "tool_node"

    # Otherwise, we stop (reply to the user)
    return END

# Step 6: Build agent

# Build workflow
agent_builder = StateGraph(MessagesState)

# Add nodes
agent_builder.add_node("llm_call", llm_call)
agent_builder.add_node("tool_node", tool_node)

# Add edges to connect nodes
agent_builder.add_edge(START, "llm_call")
agent_builder.add_conditional_edges(
    "llm_call",
    should_continue,
    ["tool_node", END]
)
agent_builder.add_edge("tool_node", "llm_call")

# Compile the agent
agent = agent_builder.compile()

# Invoke
from langchain.messages import HumanMessage
messages = [HumanMessage(content="""Use Curl and Nmap to identify how many devices are on the 192.168.50.0/24 range. Tell me what commands you used. 
Rules:
- Do NOT hallucinate services
- Output ONLY valid JSON

Output format:

{
  "target": "ip address",
  "openPorts": [
    {
      "service": "",
      "port": "",
    }
  ],
  "overall_assessment": ""
}""")]
messages = agent.invoke({"messages": messages})
