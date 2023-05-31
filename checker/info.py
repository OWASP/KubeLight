import json


def rules_info():
    f = open("info.json","r")
    return json.load(f)
