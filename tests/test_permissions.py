from allure import title
import pytest
import json

from tests.utils import strip_fuzz, draw_plain_request
from tests.allure import attach_failed_case
from jsonrpc_fuzzer.requests import send_request 


@title("Permissions check: {method_name}")
def test_permissions_method(
    method_name,
    methods_config,
    endpoint_url,
    no_permissions_session,
    permissions_test_enabled,
    vcr_logger,
    request_timeout,

):
    """
    One permission test on each method. If server respond 'result', its permissions bug.
    """
    if not permissions_test_enabled:
        pytest.skip(
            "BOLA permissions test skipped: "
            "no-permissions auth profile is not configured "
            "(--no-permissions-* flags)."
        )
    
    method_spec = methods_config[method_name]
    params_spec = method_spec.get("params", object())
    if params_spec.get("check_permissions", True) is False:
        pytest.skip(f"Method '{method_name}' skipped for check permissions")

    minimal_spec = strip_fuzz(method_spec)
    payload, _ = draw_plain_request(method_name, method_spec, minimal_spec)

    resp, err = send_request(
        method_name=method_name,
        session=no_permissions_session,
        url=endpoint_url,
        payload=payload,
        timeout=request_timeout,
        vcr_logger=vcr_logger,
    )

    if err is not None:
        attach_failed_case(payload, resp, str(err))
        pytest.fail(f"Network error on permissions test: {err}")

    if resp is not None and resp.status_code >= 500:
        attach_failed_case(payload, resp, f"Permissions bug: {resp.status_code}")
        pytest.fail(
            f"Permissions bug: server returns {resp.status_code} without "
            f"permissions. Response: {resp.text[:500]}"
        )

    if resp is not None:
        try:
            data = resp.json()
        except json.JSONDecodeError:
            attach_failed_case(payload, resp, "Invalid JSON")
            pytest.fail(f"Invalid JSON response: {resp.text[:500]}")

        if isinstance(data, dict) and "result" in data:
            attach_failed_case(payload, resp, "Permissions bug: got 'result'")
            pytest.fail(
                f"Permissions bug: server returned 'result' without "
                f"permissions. Response: {resp.text[:500]}"
            )