import itertools
import threading
import json
import allure

from jsonrpc_fuzzer.sensitive_values import (
    mask_response_text,
    mask_value,
    mask_keys, 
    try_json
)

def _mask_headers(headers) -> dict:
    if headers is None:
        return {}
    return {k: mask_keys({k: v})[k] for k, v in dict(headers).items()}


_attach_counter = itertools.count(1)
_counter_lock = threading.Lock()


def _next_case_id() -> int:
    with _counter_lock:
        return next(_attach_counter)


def attach_failed_case(payload, resp, error_msg, note=None) -> None:
    case_id = _next_case_id()
    try:
        request_headers = resp.request.headers if resp is not None else None
        combined: dict = {
            "request_headers": _mask_headers(request_headers),
            "request_body": mask_keys(try_json(payload)),
        }

        if resp is not None:
            combined["response_headers"] = _mask_headers(resp.headers)
            combined["response_body"] = try_json(mask_response_text(resp.text))
        if error_msg:
            combined["error"] = mask_value(error_msg)
        if note:
            combined["note"] = note

        status_part = f" [HTTP {resp.status_code}]" if resp is not None else " [no response]"
        
        allure.attach(
            json.dumps(combined, indent=2, ensure_ascii=False),
            f"Failed test case #{case_id}{status_part}",
            allure.attachment_type.JSON,
        )
    except Exception as e:
        try:
            allure.attach(
                f"[attach_failed_case failed: {e!r}]",
                f"Failed case #{case_id} attach_error",
                allure.attachment_type.TEXT,
            )
        except Exception:
            pass