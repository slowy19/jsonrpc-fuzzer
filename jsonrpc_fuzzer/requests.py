import json
import time
from pathlib import Path
from typing import Any
import requests

from jsonrpc_fuzzer.vcr_logger import VcrLogger


def load_method_spec(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        spec = json.load(f)
    spec.setdefault("method", path.stem)
    return spec


def build_request(method: str, params: dict | list | None = None,
                  req_id: int = 1, *, include_params: bool = True) -> str:
    req: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": req_id}
    
    if include_params:
        req["params"] = params
    
    return json.dumps(req, ensure_ascii=False)


def send_request(method_name: str, session: requests.Session, url: str,
                 payload: str, timeout: float,
                 vcr_logger: VcrLogger | None
                 ) -> tuple[requests.Response | None, requests.RequestException | None]:
    t0 = time.perf_counter()
    
    try:
        resp = session.post(url, data=payload.encode("utf-8"), timeout=timeout)
        if vcr_logger:
            vcr_logger.write_interaction(
                method_name=method_name,
                payload=payload,
                resp=resp,
                url=url,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error=None,
            )
            
        return resp, None
    except requests.exceptions.RequestException as err:
        if vcr_logger:
            vcr_logger.write_interaction(
                method_name=method_name,
                payload=payload,
                resp=None,
                url=url,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error=str(err),
            )
        return None, err


def _validate_single_rpc(obj: Any, expected_id: Any) -> tuple[bool, str]:
    if not isinstance(obj, dict):
        return False, "Response item is not an object"
    if obj.get("jsonrpc") != "2.0":
        return False, f"Bad jsonrpc version: {obj.get('jsonrpc')!r}"
    if "id" not in obj:
        return False, "Missing 'id'"
    if obj["id"] != expected_id and obj["id"] is not None:
        return False, f"id mismatch: got {obj['id']!r}, expected {expected_id!r}"

    has_result = "result" in obj
    has_error = "error" in obj
    if has_result == has_error:
        return False, "Response must have exactly one of 'result'/'error'"

    if has_error:
        err = obj["error"]
        if not isinstance(err, dict):
            return False, "'error' is not an object"
        if not isinstance(err.get("code"), int):
            return False, "'error.code' is not an integer"
        if not isinstance(err.get("message"), str):
            return False, "'error.message' is not a string"
    return True, ""


def check_response(resp: requests.Response | None, request_id: Any,
                   network_error: requests.RequestException | None,
                   *, is_batch: bool = False) -> tuple[bool, str]:
    if network_error is not None:
        return False, f"Network error (possible DoS/crash): {network_error}"
    if resp is None:
        return False, "No response"
    if resp.status_code >= 500:
        return False, f"Internal Server Error: {resp.status_code}"
    if resp.status_code == 404:
        return False, f"Not Found: {resp.status_code}"

    try:
        data = json.loads(resp.content, strict=False)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return False, f"Invalid JSON in response (HTTP {resp.status_code}): {e}"


    if is_batch:
        if not isinstance(data, list):
            return False, "Batch request, but response is not an array"
        if not data:
            return False, "Empty batch response"
        for item in data:
            ok, msg = _validate_single_rpc(item, request_id)
            if not ok:
                return False, f"Batch item invalid: {msg}"
        return True, ""

    ok, msg = _validate_single_rpc(data, request_id)
    if not ok:
        return False, f"Invalid JSON-RPC response: {msg}"
    return True, ""