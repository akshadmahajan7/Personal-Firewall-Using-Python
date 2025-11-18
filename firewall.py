import json
import argparse
import subprocess
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

# --- Configuration ---
FIREWALL_RULES = {}
LOG_FILE = "firewall.log"
# **IMPORTANT**: CHANGE THIS to your actual primary network interface (e.g., 'eth0', 'wlan0', 'Ethernet', 'Wi-Fi')
INTERFACE = "eth0" 

# --- Rule Loading Component ---

def load_rules(file_path="rules.json"):
    """Loads firewall rules and default policy from a JSON file."""
    global FIREWALL_RULES
    try:
        with open(file_path, 'r') as f:
            FIREWALL_RULES = json.load(f)
        print(f"✅ Rules loaded successfully. Default Policy: {FIREWALL_RULES.get('default_policy', 'DENY')}")
    except FileNotFoundError:
        print(f"❌ Error: Rules file not found at {file_path}. Using default DENY policy.")
        FIREWALL_RULES = {"default_policy": "DENY", "rules": []}
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON format in {file_path}. Using default DENY policy.")
        FIREWALL_RULES = {"default_policy": "DENY", "rules": []}

# --- Logging Component ---

def log_packet(packet, rule_desc):
    """Logs denied or suspicious packets to the firewall.log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract details
    src_ip = packet[IP].src if IP in packet else "N/A"
    dst_ip = packet[IP].dst if IP in packet else "N/A"
    
    protocol = "UNKNOWN"
    src_port, dst_port = "N/A", "N/A"
    
    if TCP in packet:
        protocol, src_port, dst_port = "TCP", packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        protocol, src_port, dst_port = "UDP", packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
    
    log_entry = (
        f"[{timestamp}] ACTION: DENIED | REASON: {rule_desc} | "
        f"PROTOCOL: {protocol} | SRC: {src_ip}:{src_port} | DST: {dst_ip}:{dst_port} | "
        f"PACKET_SUMMARY: {packet.summary()}\n"
    )

    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
        # Note: We don't print anything here, as the main callback handles stdout for the GUI to read.
    except Exception as e:
        # Print errors to stderr, which can be captured by the GUI wrapper
        print(f"    [ERROR] Could not write to log file: {e}", file=sys.stderr)

# --- iptables Enforcement Component (Linux Only) ---

def iptables_enforce_block(packet):
    """Dynamically adds a temporary iptables rule to drop traffic from a source IP."""
    if IP not in packet:
        return

    src_ip = packet[IP].src
    
    # Block traffic coming *to* the firewall host from this source IP
    block_command = ['iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP']
    
    try:
        # Requires root privileges (handled by the 'sudo python' execution)
        subprocess.run(block_command, check=True, capture_output=True, text=True)
        print(f"    [IPTABLES] Successfully added DROP rule for {src_ip}.")
    except subprocess.CalledProcessError as e:
        print(f"    [IPTABLES ERROR] Failed to run iptables command for {src_ip}. Ensure privileges and iptables setup.", file=sys.stderr)
    except FileNotFoundError:
        print("    [IPTABLES ERROR] 'iptables' command not found. Cannot enforce system-level block.", file=sys.stderr)

# --- Rule Matching Logic ---

def check_rules(packet):
    """
    Checks an incoming Scapy packet against the defined firewall rules.
    Returns the action ('ALLOW' or 'DENY') and the matching rule ID/description.
    """
    rules = FIREWALL_RULES.get("rules", [])
    
    src_ip, dst_ip = None, None
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    protocol_name, src_port, dst_port = None, None, None
    
    if TCP in packet: protocol_name, src_port, dst_port = "TCP", packet[TCP].sport, packet[TCP].dport
    elif UDP in packet: protocol_name, src_port, dst_port = "UDP", packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet: protocol_name = "ICMP"
        
    for rule in rules:
        # 1. Protocol Match
        rule_protocol = rule.get("protocol", "any")
        if rule_protocol != "any" and rule_protocol != protocol_name: continue

        # 2. IP Match
        if IP in packet:
            rule_src_ip = rule.get("src_ip")
            if rule_src_ip and rule_src_ip != src_ip: continue
                
            rule_dst_ip = rule.get("dst_ip")
            if rule_dst_ip and rule_dst_ip != dst_ip: continue

        # 3. Port Match
        if protocol_name in ("TCP", "UDP"):
            rule_src_port = rule.get("src_port")
            if rule_src_port and rule_src_port != src_port: continue

            rule_dst_port = rule.get("dst_port")
            if rule_dst_port and rule_dst_port != dst_port: continue

        # --- Rule Matched! ---
        action = rule.get("action", "DENY").upper()
        description = f"Rule {rule.get('id', 'N/A')}: {rule.get('description', 'No description')}"
        return action, description
    
    # --- Default Policy ---
    default_action = FIREWALL_RULES.get("default_policy", "DENY").upper()
    return default_action, "Default Policy Applied"

# --- Main Packet Callback ---

def packet_callback(packet):
    """The function executed for every packet sniffed."""
    
    if IP not in packet: return
        
    action, rule_desc = check_rules(packet)
    
    if action == 'ALLOW':
        # Send ALLOWED messages to stdout (console/GUI)
        print(f"✅ ALLOWED | {rule_desc}")
    else: # action == 'DENY'
        # Log to file and enforce block
        log_packet(packet, rule_desc)
        print(f"❌ BLOCKED | {rule_desc}")
        
        # Enforce system-level block (Linux)
        iptables_enforce_block(packet)

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Python Personal Firewall (Packet Monitor/Enforcer)")
    parser.add_argument("--config", default="rules.json", help="Path to the JSON rule configuration file.")
    parser.add_argument("--interface", default=INTERFACE, help=f"Network interface to sniff on (default: {INTERFACE}).")
    args = parser.parse_args()

    # 1. Load Rules
    load_rules(args.config)
    
    # 2. Start Sniffing
    print(f"\n--- 🛡️ Starting Firewall Monitor on interface {args.interface} ---")
    print("Press Ctrl+C to stop.")
    
    try:
        sniff(prn=packet_callback, filter="ip", store=0, iface=args.interface)
    except OSError:
        # Print critical error message to stderr for the GUI wrapper
        print(f"\nFATAL ERROR: Permission denied or interface not found. Interface: {args.interface}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n--- Firewall Monitor Stopped ---")

if __name__ == "__main__":
    import sys # Import sys here for file=sys.stderr usage
    main()
