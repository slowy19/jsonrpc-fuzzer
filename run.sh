#!/bin/bash
set -uo pipefail

# ---------- load .env ----------
if [ ! -f .env ]; then
    echo "Error: file .env not found!"
    exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [ -z "${ORIGIN:-}" ]; then
    echo "Error: ORIGIN is not set in .env"
    exit 1
fi

API_PATH="${API_PATH:-/api}"
API_URL="${ORIGIN}${API_PATH}"

rm -rf reports/
mkdir -p reports/allure-results

echo "========================================="
echo "Starting jsonrpc-fuzzer"
echo "  API URL: ${API_URL}"
echo "========================================="

MAX_EXAMPLES="${MAX_EXAMPLES:-1000}"

# ---------- base pytest args ----------
PYTEST_ARGS=(
    "--api-url=${API_URL}"
    "--no-shrink"
    "--max-examples=${MAX_EXAMPLES}"
    "--junitxml=./reports/junit.xml"
    "--alluredir=./reports/allure-results"
    "--tb=short"
    "--no-showlocals"
)

# ============================================================
#  Helper: collect auth flags for a profile
#    $1 — prefix of env vars ("AUTH" or "NOPERM")
#    $2 — prefix of pytest flags ("auth" or "no-permissions")
# ============================================================
collect_auth() {
    local ENV_PFX="$1"
    local FLAG_PFX="$2"

    local header cookie login_url
    header=$(printenv "${ENV_PFX}_HEADER" 2>/dev/null || true)
    cookie=$(printenv "${ENV_PFX}_COOKIE" 2>/dev/null || true)
    login_url=$(printenv "${ENV_PFX}_LOGIN_URL" 2>/dev/null || true)

    if [ -z "$header" ] && [ -z "$cookie" ] && [ -z "$login_url" ]; then
        return 1   # not configured
    fi

    if { [ -n "$header" ] || [ -n "$cookie" ]; } && [ -n "$login_url" ]; then
        echo "Error: [${ENV_PFX}] use either static header/cookie OR login flow, not both" >&2
        return 2
    fi

    # --- static ---
    if [ -n "$header" ]; then
        PYTEST_ARGS+=("--${FLAG_PFX}-header=${header}")
    fi
    if [ -n "$cookie" ]; then
        PYTEST_ARGS+=("--${FLAG_PFX}-cookie=${cookie}")
    fi

    # --- login flow ---
    if [ -n "$login_url" ]; then
        local login password token_path token_header token_cookie body_tpl
        login=$(printenv "${ENV_PFX}_LOGIN" || true)
        password=$(printenv "${ENV_PFX}_PASSWORD" || true)
        token_path=$(printenv "${ENV_PFX}_TOKEN_JSON_PATH" || true)
        token_header=$(printenv "${ENV_PFX}_TOKEN_HEADER" || true)
        token_cookie=$(printenv "${ENV_PFX}_TOKEN_COOKIE" || true)
        body_tpl=$(printenv "${ENV_PFX}_LOGIN_BODY_TEMPLATE" || true)

        if [ -z "$login" ] || [ -z "$password" ]; then
            echo "Error: [${ENV_PFX}] LOGIN and PASSWORD are required when LOGIN_URL is set" >&2
            return 2
        fi
        if [ -z "$token_path" ]; then
            echo "Error: [${ENV_PFX}] TOKEN_JSON_PATH is required when LOGIN_URL is set" >&2
            return 2
        fi
        if [ -z "$token_header" ] && [ -z "$token_cookie" ]; then
            echo "Error: [${ENV_PFX}] one of TOKEN_HEADER / TOKEN_COOKIE is required" >&2
            return 2
        fi

        PYTEST_ARGS+=("--${FLAG_PFX}-login-url=${login_url}")
        PYTEST_ARGS+=("--${FLAG_PFX}-login=${login}")
        PYTEST_ARGS+=("--${FLAG_PFX}-password=${password}")
        PYTEST_ARGS+=("--${FLAG_PFX}-token-json-path=${token_path}")
        if [ -n "$token_header" ]; then
            PYTEST_ARGS+=("--${FLAG_PFX}-token-header=${token_header}")
        fi
        if [ -n "$token_cookie" ]; then
            PYTEST_ARGS+=("--${FLAG_PFX}-token-cookie=${token_cookie}")
        fi
        if [ -n "$body_tpl" ]; then
            PYTEST_ARGS+=("--${FLAG_PFX}-login-body-template=${body_tpl}")
        fi
    fi

    return 0
}

# ---------- main auth profile ----------
if collect_auth "AUTH" "auth"; then
    echo "[auth] configured"
elif [ $? -eq 2 ]; then
    exit 1
else
    echo "[auth] not configured — fuzz test will run anonymously"
fi

# ---------- no-permissions auth profile ----------
if collect_auth "NOPERM" "no-permissions"; then
    echo "[auth-no-permissions] configured — BOLA test enabled"
elif [ $? -eq 2 ]; then
    exit 1
else
    echo "[auth-no-permissions] not configured — BOLA test will be skipped"
fi

echo "========================================="

uv run pytest "${PYTEST_ARGS[@]}"

JSONRPC_FUZZER_EXIT_CODE=$?

echo "========================================="
echo "Generating allure report"
echo "========================================="

allure generate reports/allure-results -o reports/allure-report --clean

echo "========================================="
echo "Results:"
echo "jsonrpc-fuzzer exit code: ${JSONRPC_FUZZER_EXIT_CODE}"
echo "Allure report: reports/allure-report"
echo "Junit report and logs in directories"
echo "========================================="

exit "${JSONRPC_FUZZER_EXIT_CODE}"