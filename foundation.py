"""

This program acts as the shared platform for all of the agents.
CYB 332 Final Project

"""

import json
import time
import uuid
import os
from pathlib import Path


# instead of hardecoding the API, for security reasons I think its better to 
# store it in the terminal session, so we should use an environment variable.
# either set the key by doing: export ANTHROPIC_API_KEY="sk-ant-..."
# OR set it before running the orchestrator agent

if not os.environ.get("ANTHROPIC_API_KEY"):
    raise EnvironmentError(
        "ANTHROPIC_API_KEY isn't set."
        "Run: export ANTHROPIC_API_KEY='insert your key here' before attempting to start the application."
        "Thank you! :D"
    )


# Session info needs to be passed between all the agents
SESSION: dict = {
    "sessionID": str(uuid.uuid4())[:8],
    "targetedIP": None,
    "scope": None,
    "recon": {},
    "vulnAnly": {},
    "fullReport": {},
    "log": [],
    "startTime": time.strftime("%Y-%m-%dT%H:%M:%S"),

}

# The line below is meant to be setup by the orchestrator during runtime.
targetedIP: str = ""

def setTarget(ip : str, scope: str) -> None:
    #initializes session via scope + IP
    global targetedIP
    targetedIP = ip
    SESSION["targetedIP"] = ip
    SESSION["scope"] = scope


def logger(agent: str, event: str, data: dict | None = None) -> None:
    # appends an event to the log
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "agent": agent,
        "event": event,
        "data": data or {},
    }

    SESSION["log"].append(entry)
    print(f"  [{entry['ts']}] [{agent}] {event}")


def saveSes() -> str:
    #saves session information to a JSON file.
    #incrementally saves, lets us look at results after each agent
    #each agent should do this. 
    Path("output").mkdir(exist_ok=True)
    path = f"output/session_{SESSION['sessionID']}.json"
    with open(path, "w") as f:
        json.dump(SESSION, f, indent=2, default=str)
    return path


