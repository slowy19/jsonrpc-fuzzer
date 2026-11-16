from pathlib import Path
import warnings
import json
from typing import Any
import re

import requests
from requests.auth import HTTPBasicAuth

import pytest
from hypothesis import HealthCheck, Phase, settings
from hypothesis.errors import HypothesisWarning

from jsonrpc_fuzzer.requests import load_method_spec
from jsonrpc_fuzzer.vcr_logger import VcrLogger
from jsonrpc_fuzzer.sensitive_values import mask_value, register_sensitive_value
from jsonrpc_fuzzer.malicious_strings import reload_fuzz_dicts


REPORTS_DIR = Path("reports/")

warnings.filterwarnings(
    "ignore",
    message="Generating overly large repr",
    category=HypothesisWarning,
)

def pytest_addoption(parser):
    g = parser.getgroup("fuzz")
    g.addoption("--api-url", required=True,
                help="Full URL of JSON-RPC 2.0 endpoint")
    g.addoption("--jsonrpc-dir", default="jsonrpc_methods/",
                help="Directory with JSON-RPC method specs (*.json)")
    g.addoption("--fuzz-dicts", default="fuzz_dicts/",
                help="Directory with *.txt payload dictionaries "
                     "(one payload per line, # comments)")
    g.addoption("--max-examples", type=int, default=1000,
                help="Hypothesis max_examples per method")
    g.addoption("--no-shrink", action="store_true",
                help="Skip Hypothesis shrinking (faster)")
    g.addoption("--request-timeout", type=float, default=5.0,
                help="HTTP timeout in seconds")

    # ----- main auth profile (optional) -----
    a = parser.getgroup(
        "auth",
        "Main auth profile (optional). Configure with EITHER "
        "static headers/cookies OR a login flow.",
    )
    a.addoption("--auth-header", action="append", default=None,
                metavar="'Name: Value'",
                help="Static header attached to every request "
                     "(repeatable). E.g. 'Authorization: Bearer xxx'")
    a.addoption("--auth-cookie", action="append", default=None,
                metavar="'Name=Value'",
                help="Static cookie attached to every request "
                     "(repeatable). E.g. 'access_token=xxx'")
    a.addoption("--auth-login-url", default=None,
                help="Login endpoint URL (login flow). "
                     "Mutually exclusive with --auth-header/--auth-cookie.")
    a.addoption("--auth-login", default=None,
                help="Login (username) for login flow")
    a.addoption("--auth-password", default=None,
                help="Password for login flow")
    a.addoption("--auth-login-body-template", default=None,
                help="If set, login is POST with this JSON body template "
                     "('{login}' and '{password}' are substituted). "
                     "If unset, login is GET with HTTP Basic Auth.")
    a.addoption("--auth-token-json-path", default=None,
                help="Dot-separated path to token in login JSON response, "
                     "e.g. 'token' or 'data.access_token'")
    a.addoption("--auth-token-header", default=None,
                help="Header template to place token, e.g. "
                     "'Authorization: Bearer {token}'")
    a.addoption("--auth-token-cookie", default=None,
                help="Cookie template to place token, e.g. "
                     "'access_token={token}'")

    # ----- no-permissions auth profile (for BOLA) -----
    n = parser.getgroup(
        "auth-no-permissions",
        "No-permissions auth profile (used by test_permissions / BOLA). "
        "Same structure as the main auth profile.",
    )
    n.addoption("--no-permissions-header", action="append", default=None,
                metavar="'Name: Value'",
                help="Static header (repeatable)")
    n.addoption("--no-permissions-cookie", action="append", default=None,
                metavar="'Name=Value'",
                help="Static cookie (repeatable)")
    n.addoption("--no-permissions-login-url", default=None,
                help="Login endpoint URL (login flow)")
    n.addoption("--no-permissions-login", default=None, help="Login")
    n.addoption("--no-permissions-password", default=None, help="Password")
    n.addoption("--no-permissions-login-body-template", default=None,
                help="JSON body template for POST login")
    n.addoption("--no-permissions-token-json-path", default=None,
                help="Dot path to token in login JSON")
    n.addoption("--no-permissions-token-header", default=None,
                help="Header template for token")
    n.addoption("--no-permissions-token-cookie", default=None,
                help="Cookie template for token")


def pytest_configure(config):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "allure-results").mkdir(parents=True, exist_ok=True)

    dicts_dir = Path(config.getoption("--fuzz-dicts"))
    if dicts_dir.exists():
        reload_fuzz_dicts(dicts_dir)
    else:
        warnings.warn(
            f"Fuzz dicts dir not found: {dicts_dir}. "
            f"Using only 2 builtin payloads.",
            stacklevel=1,
        )

    phases = [Phase.explicit, Phase.reuse, Phase.generate]
    if not config.getoption("--no-shrink"):
        phases.append(Phase.shrink)

    settings.register_profile(
        "fuzz",
        max_examples=config.getoption("--max-examples"),
        deadline=None,
        database=None,
        phases=phases,
        suppress_health_check=list(HealthCheck),
    )
    settings.load_profile("fuzz")


def pytest_generate_tests(metafunc):
    if "method_name" not in metafunc.fixturenames:
        return

    path = Path(metafunc.config.getoption("--jsonrpc-dir"))
    if not path.exists() or not path.is_dir():
        raise pytest.UsageError(f"JSON-RPC dir not found: {path}")

    files = sorted(path.rglob("*.json"))
    if not files:
        raise pytest.UsageError(f"No *.json files in {path}")

    params = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise pytest.UsageError(f"Invalid JSON in {f}: {e}") from e

        method = data.get("method")
        if not isinstance(method, str) or not method:
            raise pytest.UsageError(f"Missing or invalid 'method' in {f}")

        params.append(pytest.param(method, id=f"{f.stem}-{method}"))

    metafunc.parametrize("method_name", params)


def _sanitize_longrepr(lr):
    if isinstance(lr, str):
        return mask_value(lr)

    rc = getattr(lr, "reprcrash", None)
    if rc is not None and getattr(rc, "message", None):
        rc.message = mask_value(rc.message)

    sections = getattr(lr, "sections", None)
    if sections:
        lr.sections = [(mask_value(t), mask_value(c)) for t, c in sections]

    rt = getattr(lr, "reprtraceback", None)
    if rt is not None:
        for entry in getattr(rt, "reprentries", []):
            lines = getattr(entry, "lines", None)
            if lines:
                entry.lines = [mask_value(l) for l in lines]

    return lr


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.longrepr is not None:
        report.longrepr = _sanitize_longrepr(report.longrepr)
    if getattr(report, "sections", None):
        report.sections = [(mask_value(t), mask_value(c)) for t, c in report.sections]


def _parse_header(s: str) -> tuple[str, str]:
    name, sep, value = s.partition(":")
    if not sep:
        raise pytest.UsageError(
            f"Invalid header format, expected 'Name: Value': {s!r}"
        )
    return name.strip(), value.strip()


def _parse_cookie(s: str) -> tuple[str, str]:
    name, sep, value = s.partition("=")
    if not sep:
        raise pytest.UsageError(
            f"Invalid cookie format, expected 'Name=Value': {s!r}"
        )
    return name.strip(), value.strip()


def _resolve_json_path(data: Any, path: str) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            raise pytest.UsageError(
                f"Cannot resolve token path '{path}': "
                f"missing key/index '{part}'"
            )
    return current


_PLACEHOLDER_RE = re.compile(r"\{(login|password|token)\}")

def _fill_template(tpl: str, **values: str) -> str:
    """Single-pass placeholder substitution; safe with JSON braces."""
    return _PLACEHOLDER_RE.sub(
        lambda m: values.get(m.group(1), m.group(0)),
        tpl,
    )



def _register_header_credential(value: str) -> None:
    """Also register the credential part of 'Bearer xxx'-style values."""
    register_sensitive_value(value)
    for prefix in ("Bearer ", "Basic ", "Token "):
        if value.startswith(prefix):
            part = value[len(prefix):].strip()
            if part:
                register_sensitive_value(part)
            break


def _read_auth_config(pytestconfig, profile: str) -> tuple[list, list, dict]:
    """Returns (static_headers, static_cookies, login_cfg)."""
    if profile == "auth":
        static_headers = pytestconfig.getoption("--auth-header") or []
        static_cookies = pytestconfig.getoption("--auth-cookie") or []
        login_cfg = {
            "login_url": pytestconfig.getoption("--auth-login-url"),
            "login": pytestconfig.getoption("--auth-login"),
            "password": pytestconfig.getoption("--auth-password"),
            "body_template": pytestconfig.getoption("--auth-login-body-template"),
            "token_json_path": pytestconfig.getoption("--auth-token-json-path"),
            "token_header": pytestconfig.getoption("--auth-token-header"),
            "token_cookie": pytestconfig.getoption("--auth-token-cookie"),
        }
    else:
        static_headers = pytestconfig.getoption("--no-permissions-header") or []
        static_cookies = pytestconfig.getoption("--no-permissions-cookie") or []
        login_cfg = {
            "login_url": pytestconfig.getoption("--no-permissions-login-url"),
            "login": pytestconfig.getoption("--no-permissions-login"),
            "password": pytestconfig.getoption("--no-permissions-password"),
            "body_template": pytestconfig.getoption(
                "--no-permissions-login-body-template"),
            "token_json_path": pytestconfig.getoption(
                "--no-permissions-token-json-path"),
            "token_header": pytestconfig.getoption(
                "--no-permissions-token-header"),
            "token_cookie": pytestconfig.getoption(
                "--no-permissions-token-cookie"),
        }
    return static_headers, static_cookies, login_cfg


def _is_configured(pytestconfig, profile: str) -> bool:
    h, c, login = _read_auth_config(pytestconfig, profile)
    return bool(h or c or login["login_url"])


def _apply_static(session: requests.Session,
                  static_headers: list[str],
                  static_cookies: list[str]) -> None:
    for h in static_headers:
        name, value = _parse_header(h)
        session.headers[name] = value
        _register_header_credential(value)
    for c in static_cookies:
        name, value = _parse_cookie(c)
        session.cookies.set(name, value)
        register_sensitive_value(value)


def _apply_login(session: requests.Session, cfg: dict,
                 profile: str, timeout: float) -> None:
    login_url = cfg["login_url"]
    login = cfg["login"]
    password = cfg["password"]
    body_tpl = cfg["body_template"]
    token_path = cfg["token_json_path"]
    token_header_tpl = cfg["token_header"]
    token_cookie_tpl = cfg["token_cookie"]

    if not login or not password:
        raise pytest.UsageError(
            f"Auth profile '{profile}': login and password are required "
            f"when login_url is set"
        )
    if not token_path:
        raise pytest.UsageError(
            f"Auth profile '{profile}': token_json_path is required "
            f"when login flow is used"
        )
    if not (token_header_tpl or token_cookie_tpl):
        raise pytest.UsageError(
            f"Auth profile '{profile}': one of token_header / "
            f"token_cookie is required when login flow is used"
        )

    register_sensitive_value(password)

    if body_tpl:
        body = _fill_template(body_tpl, login=login, password=password)
        resp = session.post(
            login_url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    else:
        resp = session.get(
            login_url,
            auth=HTTPBasicAuth(login, password),
            timeout=timeout,
        )
    resp.raise_for_status()

    try:
        data = resp.json()
    except ValueError as e:
        raise pytest.UsageError(
            f"Auth profile '{profile}': login response is not JSON "
            f"(HTTP {resp.status_code}): {resp.text[:200]}"
        ) from e

    token = _resolve_json_path(data, token_path)
    if not isinstance(token, str) or not token:
        raise pytest.UsageError(
            f"Auth profile '{profile}': token at '{token_path}' "
            f"is not a non-empty string"
        )
    register_sensitive_value(token)

    if token_header_tpl:
        name, value = _parse_header(_fill_template(token_header_tpl, token=token))
        session.headers[name] = value
        _register_header_credential(value)
    if token_cookie_tpl:
        name, value = _parse_cookie(_fill_template(token_cookie_tpl, token=token))
        session.cookies.set(name, value)
        register_sensitive_value(value)


def _build_auth_session(pytestconfig, profile: str,
                        timeout: float) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "Accept": "*/*",
        "User-Agent": "jsonrpc-fuzzer/0.5",
    })

    static_headers, static_cookies, login_cfg = _read_auth_config(
        pytestconfig, profile,
    )

    has_static = bool(static_headers or static_cookies)
    has_login = bool(login_cfg["login_url"])

    if not (has_static or has_login):
        # Profile not configured — anonymous session, tests still runnable
        return session

    if has_static and has_login:
        raise pytest.UsageError(
            f"Auth profile '{profile}': use EITHER static headers/cookies "
            f"OR a login flow, not both"
        )

    if has_static:
        _apply_static(session, static_headers, static_cookies)
        return session

    _apply_login(session, login_cfg, profile, timeout)
    return session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def endpoint_url(pytestconfig):
    return pytestconfig.getoption("--api-url")


@pytest.fixture(scope="session")
def request_timeout(pytestconfig):
    return pytestconfig.getoption("--request-timeout")


@pytest.fixture(scope="session")
def methods_config(pytestconfig):
    path = Path(pytestconfig.getoption("--jsonrpc-dir"))
    result: dict[str, dict] = {}
    for f in sorted(path.rglob("*.json")):
        spec = load_method_spec(f)
        result[f.stem] = spec
    return result


@pytest.fixture(scope="session")
def auth_session(pytestconfig, request_timeout):
    """Main auth session (anonymous if not configured)."""
    return _build_auth_session(pytestconfig, "auth", request_timeout)


@pytest.fixture(scope="session")
def no_permissions_session(pytestconfig, request_timeout):
    """No-permissions auth session (anonymous if not configured)."""
    return _build_auth_session(pytestconfig, "np", request_timeout)


@pytest.fixture(scope="session")
def permissions_test_enabled(pytestconfig):
    """Whether test_permissions has a configured no-permissions profile."""
    return _is_configured(pytestconfig, "np")


@pytest.fixture(scope="session")
def vcr_logger():
    logger = VcrLogger(REPORTS_DIR / "vcr.jsonl")
    yield logger
    logger.close()