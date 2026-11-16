import json

def strip_fuzz(spec: dict) -> dict:
    if not isinstance(spec, dict):
        return spec
    
    out = {k: v for k, v in spec.items() if k != "fuzz"}
    
    if "fields" in spec:
        out["fields"] = {k: strip_fuzz(v) for k, v in spec["fields"].items()}
    if "items" in spec:
        out["items"] = strip_fuzz(spec["items"])
    
    return out


def _plain_value(spec: dict):
    if "value" in spec:
        return spec["value"]
    if "enum" in spec:
        return spec["enum"][0]
    t = spec.get("type", "string")
    match t:
        case "string":
            sw = spec.get("starts_with", "")
            ew = spec.get("ends_with", "")
            
            if sw != "" and ew != "":
                return f"{sw}x{ew}"
            elif sw != "":
                return sw
            elif ew != "":
                return ew
            else:
                return ""
        case "integer":
            return spec.get("min", 0)
        case "float":
            return 0.0
        case "boolean":
            return True
        case "null":
            return None
        case "object":
            return {k: _plain_value(v) for k, v in (spec.get("fields") or {}).items()
                    if not v.get("optional", False)}
        case "array":
            n = spec.get("min_items", 0)
            item = spec.get("items") or {"type": "string"}
            return [_plain_value(item) for _ in range(n)]
        case "uuid":
            return "00000000-0000-0000-0000-000000000000"
        case "date":
            return "2000-01-01"
        case "regex":
            return "a"
        case _:
            return "x"


def draw_plain_request(method_name: str, method_spec: dict, plain_spec: dict):
    body: dict = {"jsonrpc": "2.0", "method": method_name, "id": 1}

    params_spec = plain_spec.get("params", None)
    if params_spec is None and "params" not in plain_spec:
        pass
    elif params_spec is None:
        body["params"] = None
    else:
        body["params"] = _plain_value(params_spec)

    if method_spec.get("batch", False):
        payload = json.dumps([body], ensure_ascii=False)
    else:
        payload = json.dumps(body, ensure_ascii=False)
    return payload, body["id"]