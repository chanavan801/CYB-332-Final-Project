# AI Agent

Step 1 - Follow the instructions in this video here, using the Metasploitable Version that the Professor gave us: https://www.youtube.com/watch?v=O8FQO17yEKw. Ignore the steps for installing gvm or utilizing OpenVAS. This will set up two VM with a LAN connection. 

Step 2 - Place agent.py, vuln_agent.py, ReportWriter.py, and foundation.py onto the kali machine. 

Step 3 - On the Kali machine, run the following commands:
: sudo apt update && sudo apt install python3-venv -y
: python3 -m venv lc-env
: source lc-env/bin/activate
: pip install langchain-anthropic langchain-core langgraph langchain
NOTE - the 'source lc-env/bin/activate' command will likely need to be run on each new start up. 

Step 4 - use the provided API key and run the following:
: export ANTHROPIC_API_KEY="insert your key here"

Step 5 - run the following command, this file must run before any of the others:
: python3 foundation.py

Step 6 - run python3 agent.py
NOTE - the reportWriter.py file should be the last file that runs. The other files should run first so it can collect the results of all the other agents to generate its report. 
