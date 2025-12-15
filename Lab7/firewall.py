import socket
import json
import time
from ipaddress import ip_address, ip_network

RULES_FILE = "rules.json"
LOG_FILE = "logs.jsonl"

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
FORWARD_HOST = "example.com"
FORWARD_PORT = 80


def load_rules():
    with open(RULES_FILE) as f:
        rules = json.load(f)
    return sorted(
        [r for r in rules if r.get("enabled", True)],
        key=lambda x: x["priority"]
    )


def match(rule, src_ip, dst_port, proto):
    if proto != rule["proto"]:
        return False
    if not ip_address(src_ip) in ip_network(rule["src_ip_cidr"]):
        return False
    if rule["dst_port"] != "*" and rule["dst_port"] != dst_port:
        return False
    return True


def log_event(action, reason, src_ip, dst_port, proto):
    event = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "protocol": proto,
        "src": src_ip,
        "dst_port": dst_port,
        "reason": reason
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def start_firewall():
    s = socket.socket()
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(5)
    print("Firewall listening on port", LISTEN_PORT)

    while True:
        client, addr = s.accept()
        src_ip = addr[0]
        rules = load_rules()

        decision = "allow"
        for r in rules:
            if match(r, src_ip, LISTEN_PORT, "TCP"):
                decision = r["action"]
                break

        if decision == "deny":
            log_event("deny", "Rule matched", src_ip, LISTEN_PORT, "TCP")
            client.close()
            continue

        log_event("allow", "Allowed", src_ip, LISTEN_PORT, "TCP")
        server = socket.create_connection((FORWARD_HOST, FORWARD_PORT))
        client.sendall(server.recv(4096))
        client.close()
        server.close()


if __name__ == "__main__":
    start_firewall()
