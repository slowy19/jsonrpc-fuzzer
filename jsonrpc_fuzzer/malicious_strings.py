from hypothesis import strategies as st
from pathlib import Path


_BUILTIN_MALICIOUS_STRINGS: list[str] = [
    "\x00\x01\x02",
    "A" * 5000,
]

MALICIOUS_STRINGS: list[str] = list(_BUILTIN_MALICIOUS_STRINGS)

def _make_malicious_st():
    if MALICIOUS_STRINGS:
        return st.sampled_from(MALICIOUS_STRINGS)
    return st.none().filter(lambda _: False)

malicious_st = _make_malicious_st()


def load_fuzz_dicts(directory: Path) -> list[str]:
    if not directory.exists() or not directory.is_dir():
        raise ValueError(f"Fuzz dicts dir not found: {directory}")

    seen: set[str] = set()
    result: list[str] = []
    for f in sorted(directory.rglob("*.txt")):
        with f.open(encoding="utf-8", newline="") as fh:
            for raw in fh:
                s = raw.rstrip("\r\n")
                if not s or s.startswith("#"):
                    continue
                if s in seen:
                    continue
                seen.add(s)
                result.append(s)
    return result


def reload_fuzz_dicts(directory: Path) -> None:
    global MALICIOUS_STRINGS, malicious_st

    file_strings = load_fuzz_dicts(directory)
    MALICIOUS_STRINGS = list(_BUILTIN_MALICIOUS_STRINGS) + file_strings
    
    malicious_st = _make_malicious_st()

malicious_st = st.sampled_from(MALICIOUS_STRINGS)