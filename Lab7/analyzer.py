import json

rules = json.load(open("rules.json"))
seen = {}

for r in rules:
    key = (r["src_ip_cidr"], r["dst_port"], r["proto"])
    if key in seen:
        print("Duplicate or conflict:", r, "vs", seen[key])
    else:
        seen[key] = r
