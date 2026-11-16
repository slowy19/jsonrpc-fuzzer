import pytest
from hypothesis import given, strategies as st
from allure import title

from jsonrpc_fuzzer.requests import check_response, send_request
from jsonrpc_fuzzer.strategies import request_strategy

from tests.allure import attach_failed_case


@title("Fuzz method: {method_name}")
def test_fuzz_method(
    method_name,
    methods_config,
    endpoint_url,
    auth_session,
    vcr_logger,
    request_timeout,
):
    """
    Main test fuzz method
    """
    method_spec = methods_config[method_name]
    is_batch = bool(method_spec.get("batch", False))
    errors: list[dict] = []

    @given(data=st.data())
    def _fuzz(data):
        strat = request_strategy(method_name, method_spec)
        payload, req_id = data.draw(strat)

        resp, err = send_request(
            method_name=method_name,
            session=auth_session,
            url=endpoint_url,
            payload=payload,
            timeout=request_timeout,
            vcr_logger=vcr_logger,
        )

        ok, msg = check_response(resp, req_id, err, is_batch=is_batch)
        if not ok:
            errors.append({"payload": payload, "response": resp, "error_msg": msg})

    _fuzz()

    if not errors:
        return

    for err in errors:
        attach_failed_case(err.get("payload"), err.get("response"), err.get("error_msg"))

    pytest.fail(
        f"[{method_name}] Fuzzing found {len(errors)} failing case(s). "
        f"See Allure attachments for details."
    )