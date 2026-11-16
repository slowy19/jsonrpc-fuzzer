import datetime
import requests
from pathlib import Path
import json

from jsonrpc_fuzzer.sensitive_values import (
    mask_value,
    mask_response_text,
    try_json,
)


class VcrLogger:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._fh = path.open("a", encoding="utf-8")

    def write_interaction(self, method_name: str, payload: str,
                          resp: requests.Response | None, url: str,
                          duration_ms: float, error: str | None):
        if resp is not None:
            safe_req_body = try_json(payload)
            safe_resp_body = mask_response_text(resp.text) if resp.text else None
            req_headers = mask_value(try_json(resp.request.headers)) or {}
            resp_headers = resp.headers
            status_code = resp.status_code
        else:
            safe_req_body = "<unknown>"
            safe_resp_body = "<unknown>"
            req_headers = {}
            resp_headers = {}
            status_code = "<unknown>"

        interaction = {
            "recorded_at": datetime.datetime.now().isoformat() + "Z",
            "method": method_name,
            "request": {
                "method": "POST",
                "uri": url,
                "headers": {k: [v] for k, v in req_headers.items()},
                "body": {"string": json.dumps(safe_req_body, ensure_ascii=False)
                         if isinstance(safe_req_body, (dict, list))
                         else str(safe_req_body)},
            },
            "response": {
                "status": {"code": status_code, "message": ""},
                "headers": {k: [v] for k, v in resp_headers.items()} if resp_headers else {},
                "body": {"string": json.dumps(safe_resp_body, ensure_ascii=False)
                         if isinstance(safe_resp_body, (dict, list))
                         else str(safe_resp_body)} if safe_resp_body
                        else {"string": ""},
            },
            "duration_ms": round(duration_ms, 2),
            "error": error,
        }

        self._fh.write(json.dumps(interaction, ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self):
        self._fh.close()