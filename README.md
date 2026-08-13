 🛡️ AI-Powered Linux Network Intrusion Detection System (NIDS)

An intelligent, real-time Network Intrusion Detection System (NIDS) built for Linux. It monitors network traffic, extracts packet/flow features, classifies threats using Machine Learning, and actively responds by blocking attackers via `iptables`.



 🚀 Key Features

* Real-Time Traffic Sniffing:** Captures network packets continuously using `Scapy`.
* AI Feature Extraction:** Analyzes packet headers, protocols, TCP flags, and flow rates in real-time.
* Intelligent Classification:** Uses Machine Learning models (trained on `CICIDS2017` dataset standards) to identify attacks (DoS/DDoS, Port Scanning, Brute Force, Web Attacks, Botnets).
* Active Firewall Defense:** Direct integration with Linux `iptables` to drop malicious traffic automatically or manually.
* Live Interactive Terminal UI:** Built-in dynamic dashboard using `rich` for real-time monitoring and statistics.


 🛠️ Prerequisites & Installation

 Requirements (Linux)
* Python 3.10+
* Root / Sudo privileges (required for capturing network packets and modifying `iptables`).

 Setup

1. Clone the repository:
   
   git clone https://github.com/d2rkd2rk/ZeroTrace.git

   cd ZeroTrace

   sudo apt update && sudo apt install -y python3-pip iptables

sudo apt update && sudo apt install -y python3-scapy python3-rich python3-joblib python3-numpy


sudo python3 ZeroTrace.py -i eth0
