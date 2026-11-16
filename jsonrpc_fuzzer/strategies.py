import re
from hypothesis import strategies as st
from typing import Any
import json

from jsonrpc_fuzzer.malicious_strings import malicious_st


def make_regex_strategy(spec: dict) -> st.SearchStrategy[str]:
    pattern = spec.get("value")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"Invalid regex spec: {spec!r}")
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Bad regex in spec {spec!r}: {e}") from e
    return st.from_regex(pattern, fullmatch=True)


MAX_DEPTH = 5
_MISSING = object()


def _object_strategy(spec: dict, depth: int):
    if depth >= MAX_DEPTH:
        return st.just({})

    fields = spec.get("fields")
    fuzz = spec.get("fuzz", False)

    if not fields:
        return st.dictionaries(st.text(max_size=10), st.text(max_size=30), max_size=3)

    field_strategies = {}
    for name, field_spec in fields.items():
        strategy = field_strategy(field_spec, depth + 1)
        if field_spec.get("optional", False):
            field_strategies[name] = st.one_of(st.just(_MISSING), strategy)
        else:
            field_strategies[name] = strategy

    base = st.fixed_dictionaries(field_strategies).map(
        lambda d: {k: v for k, v in d.items() if v is not _MISSING}
    )

    if not fuzz:
        return base

    declared = set(fields.keys())
    
    extra_keys = st.text(min_size=1, max_size=10).filter(lambda k: k not in declared)
    extra_values = st.recursive(
        st.one_of(
            malicious_st,
            st.text(max_size=30),
            st.integers(min_value=-(10 ** 6), max_value=10 ** 6),
            st.floats(allow_nan=False, allow_infinity=False),
            st.booleans(),
            st.none(),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=3),
            st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=3),
        ),
        max_leaves=5,
    )
    extras = st.dictionaries(extra_keys, extra_values, max_size=3)
    
    return st.builds(lambda a, b: {**a, **b}, base, extras)


def _array_strategy(spec: dict, depth: int):
    if depth >= MAX_DEPTH:
        return st.just([])
    
    items_spec = spec.get("items")
    if items_spec is None:
        return st.lists(st.text(max_size=30), max_size=3)
    
    item_strategy = field_strategy(items_spec, depth + 1)
    return st.lists(
        item_strategy,
        min_size=spec.get("min_items", 0),
        max_size=spec.get("max_items", 3),
    )


def field_strategy(spec: dict, depth: int = 0):
    if "enum" in spec:
        return st.sampled_from(spec["enum"])
    if "value" in spec and not spec.get("fuzz", False):
        return st.just(spec["value"])

    t = spec.get("type", "string")
    match t:
        case "string":
            ends_with = spec.get("ends_with")
            starts_with = spec.get("starts_with")
            if starts_with is not None and ends_with is not None:
                return st.one_of(
                    malicious_st.map(lambda s: starts_with + s + ends_with),
                    st.text(max_size=90).map(lambda s: starts_with + s + ends_with),
                )
            if starts_with is not None:
                return st.one_of(
                    malicious_st.map(lambda s: starts_with + s),
                    st.text(max_size=90).map(lambda s: starts_with + s),
                )
            if ends_with is not None:
                return st.one_of(
                    malicious_st.map(lambda s: s + ends_with),
                    st.text(max_size=90).map(lambda s: s + ends_with),
                )
            return st.one_of(malicious_st, st.text(max_size=100))
        case "integer":
            return st.integers(
                min_value=spec.get("min", -(10 ** 9)),
                max_value=spec.get("max", 10 ** 9),
            )
        case "float":
            return st.floats(allow_nan=False, allow_infinity=False)
        case "boolean":
            return st.booleans()
        case "null":
            return st.none()
        case "object":
            return _object_strategy(spec, depth)
        case "array":
            return _array_strategy(spec, depth)
        case "date":
            return st.dates().map(lambda d: d.isoformat())
        case "uuid":
            ends_with = spec.get("ends_with")
            starts_with = spec.get("starts_with")
            generated_uuid = st.uuids().map(str)
            if starts_with is not None and ends_with is not None:
                return generated_uuid.map(lambda s: starts_with + s + ends_with)
            if starts_with is not None:
                return generated_uuid.map(lambda s: starts_with + s)
            if ends_with is not None:
                return generated_uuid.map(lambda s: s + ends_with)
            return generated_uuid
        case "regex":
            return make_regex_strategy(spec)
        case "ip":
            return st.ip_addresses(v=4).map(str)
        case _:
            return st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=100))
        

_extra_envelope_keys = st.text(min_size=1, max_size=10).filter(
    lambda k: k not in {"jsonrpc", "method", "params", "id"}
)


def build_batch(requests_: list[dict]) -> str:
    return json.dumps(requests_, ensure_ascii=False)


@st.composite
def request_strategy(draw, method_name: str, method_spec: dict):
    req_id = draw(st.one_of(
        st.integers(min_value=1, max_value=10 ** 6),
        st.text(min_size=1, max_size=10),
    ))

    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method_name, "id": req_id}

    # params
    params_spec = method_spec.get("params", _MISSING)
    if params_spec is _MISSING:
        pass
    elif params_spec is None:
        body["params"] = None
    else:
        body["params"] = draw(field_strategy(params_spec))

    # fuzz_envelope
    if method_spec.get("fuzz_envelope", False):
        mutate = draw(st.sampled_from(["none", "jsonrpc", "method", "id", "extra"]))
        match mutate:
            case "jsonrpc":
                body["jsonrpc"] = draw(st.one_of(
                    st.just("1.0"), st.just("3.0"),
                    st.integers(), st.none(), st.text(max_size=5),
                ))
            case "method":
                body["method"] = draw(st.one_of(
                    st.just(""), st.text(min_size=1, max_size=30),
                    st.integers(), st.none(),
                ))
            case "id":
                body["id"] = draw(st.one_of(
                    st.none(), st.floats(allow_nan=False),
                    st.lists(st.integers(), max_size=3),
                    st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=2),
                ))
            case "extra":
                extra = draw(st.dictionaries(
                    _extra_envelope_keys,
                    st.one_of(malicious_st, st.text(max_size=20), st.integers(), st.none()),
                    max_size=2,
                ))
                body.update(extra)

    if method_spec.get("batch", False):
        payload = build_batch([body])
    else:
        payload = json.dumps(body, ensure_ascii=False)

    return payload, req_id