import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT_DIR = "jsonrpc_methods"

DEFAULT_CHECK_PERMISSIONS = True
DEFAULT_FUZZ = True
DEFAULT_FUZZ_ENVELOPE = False
DEFAULT_BATCH = False

MAX_DEPTH = 100


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")


def sanitize_filename(method: str) -> str:
    stem = _SAFE_NAME_RE.sub("_", method)
    stem = re.sub(r"_+", "_", stem).strip("_")
    return stem or "method"


def _scalar_spec(value: Any) -> dict:
    if type(value) is bool:
        return { "type": "boolean", "fuzz": True }
    if type(value) is int:
        return { "type": "integer", "fuzz": True }
    if type(value) is float:
        return { "type": "float", "fuzz": True }
    if type(value) is str:
        return { "type": "string", "fuzz": True }
    if value is None:
        return { "type": "null" }
    raise TypeError(f"unsupported scalar type: {type(value).__name__}")


def infer_spec(value: Any, depth: int = 0) -> dict:
    if depth > MAX_DEPTH:
        raise ValueError(
            f"value nesting too deep (>{MAX_DEPTH}); "
            f"possible cycle or pathological input"
        )

    if isinstance(value, dict):
        return {
            "type": "object", 
            "fuzz": True, 
            "fields": {k: infer_spec(v, depth + 1) for k, v in value.items()},
        }

    if isinstance(value, list):
        if not value:
            return { "type": "array", "fuzz": True }
        return {
            "type": "array",
            "fuzz": True, 
            "items": infer_spec(value[0], depth + 1),
        }

    return _scalar_spec(value)


def build_params_spec(params: Any, method: str) -> dict:
    if params is None:
        return {
            "type": "object",
            "check_permissions": DEFAULT_CHECK_PERMISSIONS,
            "fuzz": DEFAULT_FUZZ,
        }

    if isinstance(params, dict):
        result: dict = {
            "type": "object",
            "check_permissions": DEFAULT_CHECK_PERMISSIONS,
            "fuzz": DEFAULT_FUZZ,
        }
        if params:
            result["fields"] = {
                k: infer_spec(v) for k, v in params.items()
            }
        return result

    if isinstance(params, list):
        result = {"type": "array"}
        if params:
            result["items"] = infer_spec(params[0])
        return result

    raise ValueError(
        f"method '{method}': 'params' must be object, array, or null, "
        f"got {type(params).__name__}"
    )


def build_spec(request: dict) -> dict:
    method = request.get("method")
    if not isinstance(method, str) or not method:
        raise ValueError(
            f"invalid or missing 'method' (must be non-empty string); "
            f"got {method!r}"
        )

    if "params" not in request:
        print(
            f"[WARN] method '{method}': no 'params' key, "
            f"generating template without 'fields'",
            file=sys.stderr,
        )
        params = None
    else:
        params = request["params"]
        if params is None:
            print(
                f"[WARN] method '{method}': 'params' is null, "
                f"generating template without 'fields'",
                file=sys.stderr,
            )

    spec: dict = {
        "method": method,
        "params": build_params_spec(params, method),
    }

    if DEFAULT_FUZZ_ENVELOPE:
        spec["fuzz_envelope"] = True
    if DEFAULT_BATCH:
        spec["batch"] = True

    return spec


def load_request(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e
    except OSError as e:
        raise ValueError(f"cannot read: {e}") from e

    if isinstance(data, list):
        raise ValueError(
            "input is a JSON array (batch?). generate_fuzz_method expects "
            "a single JSON-RPC object; generate a spec per request"
        )
    
    if not isinstance(data, dict):
        raise ValueError(
            f"expected JSON object at top level, got {type(data).__name__}"
        )
    
    return data


def process_file(src: Path, out_dir: Path) -> Path:
    request = load_request(src)
    spec = build_spec(request)

    stem = sanitize_filename(spec["method"])
    out_path = out_dir / f"{stem}.json"

    out_dir.mkdir(parents=True, exist_ok=True)

    if out_path.exists():
        print(f"[WARN] overwriting existing file: {out_path}", file=sys.stderr)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=4)
        f.write("\n")

    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate JSON-RPC 2.0 fuzzing spec files "
            "from example requests."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="single .json request file, or a directory with .json files",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path(DEFAULT_OUTPUT_DIR),
        help=f"output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="recurse into subdirectories when input is a directory",
    )
    args = parser.parse_args(argv)

    inp: Path = args.input
    out_dir: Path = args.output

    if not inp.exists():
        print(f"[ERROR] input path does not exist: {inp}", file=sys.stderr)
        return 2

    if inp.is_file():
        if inp.suffix.lower() != ".json":
            print(
                f"[ERROR] input file must have .json extension: {inp}",
                file=sys.stderr,
            )
            return 2
        files = [inp]
    elif inp.is_dir():
        pattern = "**/*.json" if args.recursive else "*.json"
        files = sorted(p for p in inp.glob(pattern) if p.is_file())
        if not files:
            print(f"[WARN] no .json files found in {inp}", file=sys.stderr)
            return 0
    else:
        print(
            f"[ERROR] input is neither file nor directory: {inp}",
            file=sys.stderr,
        )
        return 2

    ok = failed = 0
    for f in files:
        try:
            out = process_file(f, out_dir)
            print(f"[OK] {f} -> {out}")
            ok += 1
        except Exception as e:
            print(f"[ERROR] {f}: {e}", file=sys.stderr)
            failed += 1

    print(f"\nDone: {ok} ok, {failed} failed", file=sys.stderr)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())