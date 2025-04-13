# protocol.py

import json

def build_request(req_type, data):
    return json.dumps({
        "type": req_type,
        "data": data
    }).encode()

def parse_request(raw_data):
    try:
        data = json.loads(raw_data.decode())
        return data.get("type"), data.get("data")
    except Exception:
        return None, None

def build_response(success, result):
    return json.dumps({
        "success": success,
        "result": result
    }).encode()

def parse_response(raw_data):
    try:
        data = json.loads(raw_data.decode())
        return data.get("success"), data.get("result")
    except Exception:
        return False, "Invalid response"
