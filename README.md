# 🔥 Python Personal Firewall
A lightweight, user-defined firewall developed in Python to monitor and filter network traffic based on custom rule sets. This tool is designed for educational purposes and personal network auditing.

## 🌟 Features
* **Packet Sniffing:** Utilizes **Scapy** to intercept and analyze incoming and outgoing network packets.
* **Rule-Based Filtering:** Allows users to define rules to **allow** or **deny** traffic based on:
  * Source/Destination IP Addresses
  * Source/Destination Ports
  * Network Protocols (TCP, UDP, ICMP, etc.)
* **Suspicious Activity Logging:** Maintains a detailed log of all packets that violate a configured rule or are otherwise deemed suspicious.
* **System-Level Integration (Linux):** Optional module to interface with iptables to enforce firewall rules at the operating system kernel level for robust protection.
* **Interactive Monitoring (Optional GUI):** A planned **Tkinter** (or similar) interface for real-time monitoring of traffic and easy rule management.

---

## 💻 Prerequisites
To run and develop this project, you will need the following:
* **Python 3.x**
* **Scapy:** A powerful interactive packet manipulation tool.
* `libpcap` / `WinPcap` / `Npcap` (OS-dependent requirement for Scapy)
* `iptables` (Required for system-level enforcement on Linux)
* `tkinter` (Required for the optional GUI)

---

## 🛠️ Installation
1. Clone the repository:
```bash
git clone https://github.com/YourUsername/Python-Personal-Firewall.git
cd Python-Personal-Firewall
```
2. Install dependencies: It is highly recommended to use a virtual environment.
```bash
python -m venv venv
source venv/bin/activate  # On Linux/macOS
# .\venv\Scripts\activate  # On Windows

pip install scapy
# If developing the GUI:
# pip install tk
```
3.Permissions Note: Sniffing network traffic often requires root (Linux/macOS) or Administrator (Windows) privileges.
```bash
#Linux
sudo python firewall.py

#Windows
#Using Command Prompt (cmd)
#Click the Start Menu.
#Type cmd (or Command Prompt).
#Right-click on the "Command Prompt" app and select "Run as administrator".
#Navigate to your project directory (e.g., cd C:\Users\YourName\Python-Personal-Firewall).
#Run the script:
python firewall.py
```

---

## 🚀 Usage
The firewall can be run in CLI or GUI mode.
1. Defining RulesRules are defined in a configuration file (e.g., `rules.json` or `rules.txt`)
2. Running the Firewall (CLI)
   ```bash
   python firewall.py --config <path/to/rules.json>
   ```
3. Running the Firewall (GUI - If implemented)
   ```bash
   python firewall_gui.py
   ```
This will launch the live monitoring dashboard.

---

## ⚙️ Implementation Details
### **A. Packet Sniffing with Scapy**
The core functionality will use Scapy's `sniff()` function, applying a custom callback function to each intercepted packet.
```python
from scapy.all import sniff

def packet_callback(packet):
    # Logic to check packet against defined rules
    if is_suspicious(packet):
        log_packet(packet)
    elif check_rules(packet) == 'BLOCK':
        # Implement packet dropping mechanism (e.g., using a filter)
        print(f"BLOCKED: {packet.summary()}")
    else:
        print(f"ALLOWED: {packet.summary()}")

# sniff(prn=packet_callback, filter="ip", store=0, iface="eth0")
```
### **B. Rule Enforcement and Packet Filtering**
The check_rules() function will iterate through the loaded ruleset. The firewall should operate on a default deny or default allow policy, with explicit rules overriding the default.

### **C. Logging**
All dropped or suspicious packets will be written to a file (firewall.log) with a timestamp, packet summary, and the reason for the action.

### **D. System Integration with iptables (Linux)**
For true system-level filtering, a module can be created to dynamically add rules to iptables using Python's subprocess module.
```python
import subprocess

def block_ip_via_iptables(ip):
    # Blocks all traffic from a specific IP using the system's iptables
    command = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
    try:
        subprocess.run(command, check=True)
        print(f"iptables: Successfully blocked {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Error running iptables command: {e}")
```

---

## 🤝 Contributing
Contributions are welcome! Please feel free to open issues or submit pull requests for:
* Improving the rule matching logic and efficiency.
* Adding more sophisticated logging features (e.g., database integration).
* Developing the comprehensive GUI with live stats.
* Extending support for other OS firewall APIs (e.g., Windows Filtering Platform).

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
