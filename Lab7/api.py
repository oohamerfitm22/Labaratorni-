from flask import Flask, request, jsonify
import json

app = Flask(__name__)
RULES_FILE = "rules.json"


def load():
    with open(RULES_FILE) as f:
        return json.load(f)


def save(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


@app.route("/rules", methods=["GET"])
def get_rules():
    return jsonify(load())


@app.route("/rules", methods=["POST"])
def add_rule():
    rules = load()
    rule = request.json
    rule["id"] = max(r["id"] for r in rules) + 1 if rules else 1
    rules.append(rule)
    save(rules)
    return jsonify(rule), 201


@app.route("/rules/<int:rid>", methods=["PATCH"])
def toggle_rule(rid):
    rules = load()
    for r in rules:
        if r["id"] == rid:
            r["enabled"] = not r.get("enabled", True)
    save(rules)
    return jsonify(rules)


@app.route("/rules/<int:rid>", methods=["DELETE"])
def delete_rule(rid):
    rules = [r for r in load() if r["id"] != rid]
    save(rules)
    return jsonify(rules)


app.run(port=5000)
