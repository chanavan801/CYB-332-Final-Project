# AI Agent

Step 1 - run the following command:
```
git clone https://github.com/chanavan801/CYB-332-Final-Project
```
Step 2 - On the Kali machine, run the following commands:
```
sudo apt update
sudo apt install python3-venv -y
python3 -m venv lc-env
source lc-env/bin/activate
pip install langchain-anthropic langchain-core langgraph langchain
```
NOTE - the 'source lc-env/bin/activate' command will likely need to be run on each new start up. 

Step 3 - use a Claude API key and run the following:
```
export ANTHROPIC_API_KEY="insert your key here"
```

Step 4 - run the following command, replacing NETWORK with the network you wish to scan:
```
python3 orchestrator.py <NETWORK>
```
Additonall Note: If you want to set up a LAN using VMware, follow the instructions in this video here, using the Metasploitable Version that was provided in the assignment: https://www.youtube.com/watch?v=O8FQO17yEKw. Ignore the steps for installing gvm or utilizing OpenVAS. This will set up two Virtual Machines with a LAN connection. 
