#!/usr/bin/env python3
"""A conformance check for Wake's snapshot format.

Written against `docs/snapshot-format.md` alone, in a language Wake is not
written in, to answer a question the specification asserts but had never
demonstrated: can a consumer actually be built from the document?

It implements the four obligations of §6 and reports on each, so it doubles as
a worked example of what "conforming" means:

  §6.1  check schema_version before trusting anything
  §6.2  never read a directory whose name begins with '.'
  §6.3  surface non-zero drop counters
  §6.4  tolerate unknown fields, classes, trigger types and drop boundaries

Usage:  python3 conformance.py <snapshots-root-or-snapshot-dir>
Exit:   0 if every snapshot read cleanly, 1 otherwise.

It is deliberately dependency-light (stdlib plus either the `zstandard` module
or the `zstdcat` binary) and deliberately *not* Go: Wake's contract is the
bytes on disk, not a language binding, and a reference reader written in Go
would not have tested that claim.

This file is an example, not a supported tool. Copy it, do not depend on it.
"""

import json
import subprocess
import sys
from pathlib import Path

# §6.1 — the version this reader was written against.
SUPPORTED_SCHEMA = 1

# §3.1 — classes the document defines. Anything else is tolerated (§6.4).
KNOWN_CLASSES = {"exec", "exit", "signal", "oom", "open", "connect", "generic"}

# §2.5 — boundaries the document defines. watch_fanout is explicitly excluded
# from completeness judgements.
COMPLETENESS_BOUNDARIES = {"kernel_ringbuf", "decode", "userspace_ring"}


def decompress(path: Path) -> str:
    """Decompress a zstd file. The document says 'any standard zstd decoder'."""
    try:
        import zstandard  # noqa: PLC0415
    except ImportError:
        return subprocess.run(
            ["zstdcat", str(path)], capture_output=True, text=True, check=True
        ).stdout
    return zstandard.ZstdDecompressor().decompress(path.read_bytes()).decode()


def find_snapshots(root: Path) -> list[Path]:
    """§6.2: a directory beginning with '.' is a write in progress, never a
    snapshot. Reading one yields a truncated stream indistinguishable from a
    short capture."""
    if (root / "manifest.json").is_file():
        return [root]

    out, skipped = [], []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            skipped.append(child.name)
            continue
        out.append(child)

    for name in skipped:
        print(f"  [§6.2] skipped in-progress write: {name}")
    return out


def read_snapshot(path: Path) -> bool:
    """Read one snapshot, honouring every obligation. Returns True if usable."""
    print(f"\n=== {path.name}")

    manifest = json.loads((path / "manifest.json").read_text())

    # §6.1 — version first, before trusting any other field.
    version = manifest.get("schema_version")
    if version != SUPPORTED_SCHEMA:
        if isinstance(version, int) and version > SUPPORTED_SCHEMA:
            print(f"  [§6.1] REFUSING: schema_version {version} is newer than "
                  f"the {SUPPORTED_SCHEMA} this reader understands")
            return False
        print(f"  [§6.1] REFUSING: unrecognised schema_version {version!r}")
        return False
    print(f"  [§6.1] schema_version {version}: understood")

    trigger = manifest.get("trigger", {})
    print(f"  trigger: {trigger.get('type')} — {trigger.get('reason', '(no reason)')}")

    # §6.3 — the obligation that costs the truth if ignored.
    lost = {}
    for boundary, classes in manifest.get("drops", {}).items():
        if boundary not in COMPLETENESS_BOUNDARIES:
            continue
        for cls, n in classes.items():
            if n:
                lost[f"{boundary}.{cls}"] = n
    if lost:
        total = sum(lost.values())
        detail = ", ".join(f"{k}={v}" for k, v in sorted(lost.items()))
        print(f"  [§6.3] INCOMPLETE: {total} event(s) lost before capture ({detail}).")
        print("         Any conclusion drawn from this timeline must allow for the gap.")
    else:
        print("  [§6.3] complete: no events were lost")

    # §3 — events, oldest first.
    lines = [ln for ln in decompress(path / "events.jsonl.zst").split("\n") if ln.strip()]
    events = [json.loads(ln) for ln in lines]

    declared = manifest.get("event_count")
    if declared is not None and declared != len(events):
        print(f"  MISMATCH: manifest says {declared} events, file has {len(events)}")
        return False

    # §6.4 — tolerate the unknown rather than failing on it.
    seen, unknown, generic = {}, set(), 0
    for e in events:
        cls = e.get("class", "(absent)")
        seen[cls] = seen.get(cls, 0) + 1
        if cls not in KNOWN_CLASSES:
            unknown.add(cls)
        if cls == "generic":
            generic += 1
            # The document says a generic event retains its raw payload; a
            # reader that discards these re-creates the silent loss the class
            # exists to prevent.
            if "raw" not in e:
                print(f"  WARNING: generic event carries no raw payload")

    print(f"  {len(events)} events: " +
          ", ".join(f"{k}={v}" for k, v in sorted(seen.items())))
    if unknown:
        print(f"  [§6.4] tolerated {len(unknown)} unknown class(es): {sorted(unknown)}")
    if generic:
        print(f"  [§6.4] retained {generic} generic event(s) — records Wake "
              f"could not decode, kept rather than dropped")

    # §3 — the ordering guarantee a consumer may rely on. Note the document's
    # warning: fractional digits are trimmed, so timestamps must be parsed
    # rather than compared as strings.
    stamps = [e["ts"] for e in events if "ts" in e]
    parsed = [_parse_ts(t) for t in stamps]
    if parsed != sorted(parsed):
        print("  ORDERING VIOLATION: events are not oldest-first")
        return False
    print("  ordering: oldest-first, as guaranteed")

    # §3.4 — a failing syscall carries ret and errno together.
    failures = [e for e in events
                if isinstance(e.get("ret"), int) and e["ret"] < 0]
    for e in failures:
        if "errno" not in e:
            print(f"  CONTRACT VIOLATION: ret={e['ret']} without an errno")
            return False
    if failures:
        print(f"  {len(failures)} failed syscall(s), each with an errno")

    return True


def _parse_ts(text: str):
    """RFC 3339 with any number of fractional digits (docs §8 warns of this).

    Two traps, both hit while writing this:

    1. Wake emits nanoseconds; Python parses at most microseconds, so the
       fraction must be truncated rather than handed over whole.
    2. Truncating naively eats the timezone. "…06.998Z" becomes
       "…06.998+00:00", and scanning for digits after the "." collects the
       offset's digits too — producing a naive datetime that then cannot be
       compared with an aware one. Split the offset off *first*.
    """
    from datetime import datetime

    t = text.strip()
    offset = ""
    if t.endswith("Z"):
        t, offset = t[:-1], "+00:00"
    else:
        for i in range(len(t) - 1, max(len(t) - 7, 0), -1):
            if t[i] in "+-":
                t, offset = t[:i], t[i:]
                break

    if "." in t:
        head, _, frac = t.partition(".")
        t = f"{head}.{frac[:6]:<06}"

    return datetime.fromisoformat(t + offset)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    root = Path(sys.argv[1])
    snapshots = find_snapshots(root)
    if not snapshots:
        print(f"no snapshots under {root}")
        return 1

    ok = all([read_snapshot(s) for s in snapshots])
    print("\n" + ("CONFORMANT: every snapshot read cleanly"
                  if ok else "FAILED: see above"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
