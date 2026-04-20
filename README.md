# AI Agent

Step 1 - Follow the instructions in this video here, using the Metasploitable Version that the Professor gave us: https://www.youtube.com/watch?v=O8FQO17yEKw. Ignore the steps for installing gvm or utilizing OpenVAS. This will set up two VM with a LAN connection. 

Step 2 - Place agent.py onto the kali machine. 

Step 3 - On the Kali machine, run the following commands:
: sudo apt update && sudo apt install python3-venv -y
: python3 -m venv lc-env
: source lc-env/bin/activate
NOTE - the last command will likely need to be run on each new start up. 

Step 4 - run python3 agent.py
