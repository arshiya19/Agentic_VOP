"""Structured file edit — the shell-free write primitive.

Replaces `sed -i` / `cat > file << EOF` for source-code edits. The LLM emits
a structured spec (path, old_text, new_text) instead of shell commands. The
executor here does an exact-string replace via SSM using a base64-encoded
Python one-liner, so no shell quoting is involved anywhere in the pipeline.

Why this exists:
    Shell quoting is genuinely brittle. Every language has patterns that
    break sed differently (Python f-strings, JS template literals, HCL
    heredocs, Java generics, YAML flow style). Every new scanner scales
    the failure surface. This tool eliminates the whole class of bug by
    never involving shell parsing of the payload.

Universal (no fine-tuning, no scanner-specific logic):
    - Works for any file on any target instance
    - Zero language awareness — just bytes in, bytes out
    - Zero scanner awareness — same tool for semgrep/checkov/bandit/etc.
    - Zero env-specific values

Safety:
    - old_text MUST match exactly ONCE in the file (else refuse — forces LLM
      to include enough context to uniquely locate the edit).
    - Backup is written before every edit (path.bak-<timestamp>).
    - Base64 encoding around the SSM payload → curly braces, quotes,
      backslashes, non-ASCII all pass through cleanly.

Contract:
    Called by CodeEditStrategy when a step's Command block starts with the
    `#EDIT_FILE` marker followed by a JSON object:

        Command:
            #EDIT_FILE
            {"path": "/opt/vuln-labs/appsec-lab/app.py",
             "old_text": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
             "new_text": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"}
"""

from __future__ import annotations

import base64
import json


# The Python one-liner that runs on the target via SSM. Reads the file,
# validates old_text matches exactly once, auto-preserves indentation for
# multi-line new_text, writes with new_text substituted.
# Payload is passed via env vars (EDIT_PATH / EDIT_OLD_B64 / EDIT_NEW_B64)
# so nothing in the payload gets shell-parsed.
#
# INDENT PRESERVATION (v2): For multi-line edits, the LLM often composes
# new_text without accounting for the indentation of the line being replaced.
# Example: replacing `x = pickle.loads(d)` (indented 4 spaces inside a
# function) with `import json\nx = json.loads(d)` — the `import json` line
# ends up at column 0 while `x = json.loads` correctly aligns at column 4,
# producing an IndentationError at py_compile time.
# Fix: detect the leading whitespace of the line where old_text starts.
# Prepend that indent to every line of new_text EXCEPT the first (first
# already sits where old_text sits). NO-OP for single-line edits.
_EXECUTOR_SCRIPT = r"""
import base64, os, sys
path = os.environ["EDIT_PATH"]
old_text = base64.b64decode(os.environ["EDIT_OLD_B64"]).decode("utf-8")
new_text = base64.b64decode(os.environ["EDIT_NEW_B64"]).decode("utf-8")
try:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
except FileNotFoundError:
    sys.stderr.write(f"EDIT_ERROR: file not found: {path}\n")
    sys.exit(2)
count = content.count(old_text)
if count == 0:
    # Not necessarily an error — the file may already be at the desired
    # state (prior edit landed, or scanner reported drift). Use SKIPPED
    # phrasing so trace consumers can distinguish "we tried and old_text
    # was gone" from "we tried and hit a genuine problem."
    sys.stderr.write(f"EDIT_SKIPPED: old_text no longer present in {path} "
                     f"(file may already be at desired state)\n")
    sys.stderr.write(f"  old_text preview: {old_text[:200]!r}\n")
    sys.exit(3)
if count > 1:
    sys.stderr.write(f"EDIT_ERROR: old_text matches {count} times in {path} (must be unique)\n")
    sys.stderr.write(f"  old_text preview: {old_text[:200]!r}\n")
    sys.stderr.write("  Include more context lines to make old_text unique.\n")
    sys.exit(4)
# Auto-preserve indentation for multi-line new_text.
if "\n" in new_text:
    match_idx = content.find(old_text)
    line_start = content.rfind("\n", 0, match_idx) + 1
    leading_ws = ""
    for ch in content[line_start:match_idx]:
        if ch in (" ", "\t"):
            leading_ws += ch
        else:
            break
    if leading_ws:
        lines = new_text.split("\n")
        for i in range(1, len(lines)):
            if lines[i] and not lines[i].startswith((" ", "\t")):
                lines[i] = leading_ws + lines[i]
        new_text = "\n".join(lines)
new_content = content.replace(old_text, new_text, 1)
with open(path, "w", encoding="utf-8") as f:
    f.write(new_content)
print(f"EDIT_OK: {path} — {len(old_text)} chars replaced with {len(new_text)} chars")
""".strip()


# Marker the LLM emits so CodeEditStrategy knows to parse the block as a
# structured edit instead of running it as shell.
EDIT_FILE_MARKER = "#EDIT_FILE"


# ----------------------------------------------------------------------------
# Structured verify — pattern-absence check (post-edit sanity)
# ----------------------------------------------------------------------------
# The LLM keeps mis-composing grep-based verify shell commands: forgetting
# `|| true` (grep exits 1 on zero matches → step fails on intended zero-match
# state), unterminating quotes, mis-escaping regex metacharacters. Same
# problem class as sed for edits: shell is the wrong interface for a simple
# "is this substring gone from the file?" check.
#
# #VERIFY_ABSENT delegates that check to a Python one-liner. Payload passed
# via env vars (base64) so patterns with quotes / curly braces / regex chars
# all pass through untouched.
#
# Example emitted step:
#   Command:
#       #VERIFY_ABSENT
#       {"path": "/opt/vuln-labs/appsec-lab/app.py",
#        "pattern": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"}
#
# Exit codes:
#   0 → pattern absent (success — vulnerable code removed)
#   3 → pattern still present (fix incomplete)
#   2 → file not found
VERIFY_ABSENT_MARKER = "#VERIFY_ABSENT"
_VERIFY_ABSENT_SCRIPT = r"""
import base64, os, sys
path = os.environ["VERIFY_PATH"]
pattern = base64.b64decode(os.environ["VERIFY_PATTERN_B64"]).decode("utf-8")
try:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
except FileNotFoundError:
    sys.stderr.write(f"VERIFY_ERROR: file not found: {path}\n")
    sys.exit(2)
count = content.count(pattern)
if count > 0:
    sys.stderr.write(f"VERIFY_FAILED: pattern still present in {path} ({count} occurrence(s))\n")
    sys.stderr.write(f"  pattern preview: {pattern[:200]!r}\n")
    sys.exit(3)
print(f"VERIFY_OK: pattern absent from {path}")
""".strip()


def parse_verify_absent_spec(step_text: str) -> dict[str, str] | None:
    """Extract {path, pattern} from a step's Command block if it starts
    with the #VERIFY_ABSENT marker. Returns None if marker not present.
    Raises ValueError on malformed spec (caller propagates to LLM).
    """
    if VERIFY_ABSENT_MARKER not in step_text:
        return None
    import json  # noqa: PLC0415

    after = step_text.split(VERIFY_ABSENT_MARKER, 1)[1].strip()
    if after.endswith("```"):
        after = after[:-3].rstrip()
    start = after.find("{")
    if start < 0:
        raise ValueError("VERIFY_ABSENT marker found but no JSON object followed")
    depth, in_str, esc, end = 0, False, False, -1
    for i in range(start, len(after)):
        ch = after[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        raise ValueError("VERIFY_ABSENT JSON object never closed")
    try:
        spec = json.loads(after[start:end])
    except json.JSONDecodeError as e:
        raise ValueError(f"VERIFY_ABSENT JSON parse failed: {e}") from e
    for field in ("path", "pattern"):
        if field not in spec:
            raise ValueError(f"VERIFY_ABSENT missing required field: {field!r}")
        if not isinstance(spec[field], str):
            raise ValueError(f"VERIFY_ABSENT field {field!r} must be a string")
    if not spec["path"].startswith("/"):
        raise ValueError(f"VERIFY_ABSENT path must be absolute: {spec['path']!r}")
    if not spec["pattern"]:
        raise ValueError("VERIFY_ABSENT pattern cannot be empty")
    return spec


def build_verify_absent_ssm_command(spec: dict[str, str]) -> str:
    """Compose SSM shell command for a pattern-absence check.
    Same base64 transport pattern as build_ssm_command → no shell parsing
    of the payload. Single-quoted Python wrapper (same lesson as edit_file)."""
    path = spec["path"]
    pattern_b64 = base64.b64encode(spec["pattern"].encode("utf-8")).decode("ascii")
    path_shell = "'" + path.replace("'", "'\\''") + "'"
    return (
        f"VERIFY_PATH={path_shell} "
        f"VERIFY_PATTERN_B64='{pattern_b64}' "
        f"python3 -c '{_VERIFY_ABSENT_SCRIPT}'"
    )


def summarize_verify_absent(spec: dict[str, str]) -> str:
    prev = (spec["pattern"][:60] + "…") if len(spec["pattern"]) > 60 else spec["pattern"]
    return f"verify_absent {spec['path']}: pattern must NOT contain {prev!r}"


def is_verify_absent_step(step_text: str) -> bool:
    return VERIFY_ABSENT_MARKER in (step_text or "")


def parse_edit_spec(step_text: str) -> dict[str, str] | None:
    """Extract the {path, old_text, new_text} spec from a step's Command block.

    Returns None if the block doesn't contain the marker. Raises ValueError
    on malformed JSON or missing fields — caller propagates the error to the
    LLM so it can retry with corrected output.
    """
    if EDIT_FILE_MARKER not in step_text:
        return None
    # Take everything after the marker until end-of-block. Strip trailing fence.
    after = step_text.split(EDIT_FILE_MARKER, 1)[1].strip()
    # Trim trailing markdown fence if present
    if after.endswith("```"):
        after = after[:-3].rstrip()
    # Find first `{` and its matching balanced-brace close (string-aware)
    start = after.find("{")
    if start < 0:
        raise ValueError("EDIT_FILE marker found but no JSON object followed")
    depth = 0
    in_str = False
    esc = False
    end = -1
    for i in range(start, len(after)):
        ch = after[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        raise ValueError("EDIT_FILE JSON object never closed")
    raw_json = after[start:end]
    try:
        spec = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"EDIT_FILE JSON parse failed: {e}") from e
    for field in ("path", "old_text", "new_text"):
        if field not in spec:
            raise ValueError(f"EDIT_FILE missing required field: {field!r}")
        if not isinstance(spec[field], str):
            raise ValueError(f"EDIT_FILE field {field!r} must be a string")
    if not spec["path"].startswith("/"):
        raise ValueError(f"EDIT_FILE path must be absolute (starts with /): {spec['path']!r}")
    if spec["old_text"] == spec["new_text"]:
        raise ValueError("EDIT_FILE old_text and new_text are identical — no-op edit rejected")
    return spec


def build_ssm_command(spec: dict[str, str]) -> str:
    """Compose the SSM shell command that applies the edit safely.

    All payload bytes go through env vars set from base64 — the shell never
    parses the file contents, so quoting/curly-brace/backslash issues cannot
    occur. Python decodes on the target and does the actual replace.
    """
    path = spec["path"]
    old_b64 = base64.b64encode(spec["old_text"].encode("utf-8")).decode("ascii")
    new_b64 = base64.b64encode(spec["new_text"].encode("utf-8")).decode("ascii")
    # Path is user-controlled but constrained to absolute paths above. Wrap
    # in single quotes with any embedded single quote closed-escape-reopened.
    path_shell = "'" + path.replace("'", "'\\''") + "'"
    # CRITICAL — wrap the Python script in SINGLE quotes, not double. The
    # script contains double quotes (os.environ["EDIT_PATH"], "utf-8", etc.);
    # double-quoted shell wrapping terminates the string at the first inner
    # `"`, and downstream shell parses the rest as commands → syntax error.
    # Single-quoted shell string is fully literal — no interpolation, no
    # escape handling. We verified _EXECUTOR_SCRIPT has NO single quotes
    # so this is safe. If you ever add a `'` to the script, base64-encode it
    # instead (see the # BEFORE_EDIT comment below for the fallback pattern).
    return (
        f"EDIT_PATH={path_shell} "
        f"EDIT_OLD_B64='{old_b64}' "
        f"EDIT_NEW_B64='{new_b64}' "
        f"python3 -c '{_EXECUTOR_SCRIPT}'"
    )


def summarize_spec(spec: dict[str, str]) -> str:
    """One-line trace-friendly summary of an edit spec (for logs)."""
    old_prev = (spec["old_text"][:60] + "…") if len(spec["old_text"]) > 60 else spec["old_text"]
    new_prev = (spec["new_text"][:60] + "…") if len(spec["new_text"]) > 60 else spec["new_text"]
    return f"edit_file {spec['path']}: {old_prev!r} → {new_prev!r}"


def is_edit_file_step(step_text: str) -> bool:
    """Cheap check — does this step text contain the EDIT_FILE marker?"""
    return EDIT_FILE_MARKER in (step_text or "")


# =============================================================================
# Version-bump sanity check
# =============================================================================
# When an EDIT_FILE is a dependency version pin bump (e.g. `flask==1.0` →
# `flask==2.3.3`), catch a couple of common LLM hallucination classes BEFORE
# dispatching to SSM. Fires generically for any `<pkg>==<version>` edit — no
# scanner-specific logic, no rule-specific mapping. Non-version edits (source
# code, HCL, etc.) fall through with `None` and are handled normally.
# =============================================================================

import re as _re  # noqa: E402

# Matches "pkg==1.2.3", "pkg==1.2.3rc1", "pkg==1.2.3.post1", etc. The version
# capture is deliberately permissive — we compare as opaque tuples, not per
# any specific spec (PEP 440 / SemVer). Enough to catch the common
# hallucination classes we've observed.
_VERSION_PIN_RE = _re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)\s*$")


def _parse_pin(text: str) -> tuple[str, str] | None:
    """Return (pkg, version) if text looks like a single `pkg==version` pin,
    else None. Strips surrounding whitespace/quotes so it handles both the
    raw file line and JSON-encoded old_text."""
    if not text:
        return None
    m = _VERSION_PIN_RE.match(text.strip().strip("\"'"))
    if not m:
        return None
    return m.group(1).lower(), m.group(2)


def _version_key(v: str) -> tuple:
    """Split a version string into a comparable tuple. Integer parts sort
    numerically, non-integer (rc/alpha/post/etc) parts sort lexicographically
    AFTER integers of the same position. Good enough for detecting obvious
    ordering issues without a full PEP 440 parser."""
    parts = _re.split(r"[.\-+]", v)
    key: list[tuple[int, int | str]] = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))  # numeric first
        else:
            key.append((1, p))  # then string
    return tuple(key)


def sanity_check_version_edit(spec: dict[str, str]) -> str | None:
    """Inspect an EDIT_FILE spec for common version-bump hallucinations.

    Returns a human-readable skip reason if the edit should be skipped, or
    `None` if the edit looks OK / isn't a version pin (fall through to
    normal execution).

    Detects:
      - Same-version bump (`pkg==X → pkg==X`) — no-op, LLM hallucinated a
        different-looking spec that means nothing.
      - Downgrade attempt (`pkg==NEW → pkg==OLD`) — would REINTRODUCE the
        vulnerability, not fix it.
      - Package-name mismatch (`old_text: pkg-A==X → new_text: pkg-B==Y`) —
        LLM swapped packages, definitely a hallucination for a version bump.

    Non-detections (return None, execute normally):
      - Non-version edits (source code, HCL, YAML, JSON, etc.)
      - Version bumps that look plausible (upgrade to higher version)
      - Any edit where either side isn't a clean single `pkg==version` line
    """
    old_pin = _parse_pin(spec.get("old_text") or "")
    new_pin = _parse_pin(spec.get("new_text") or "")

    # If either side isn't a version pin, this isn't a bump — skip check
    if not old_pin or not new_pin:
        return None

    old_pkg, old_ver = old_pin
    new_pkg, new_ver = new_pin

    if old_pkg != new_pkg:
        return (
            f"package name changed ({old_pkg!r} → {new_pkg!r}) — "
            f"unusual for a version bump, likely hallucination"
        )

    if old_ver == new_ver:
        return f"same-version no-op ({old_pkg}=={old_ver})"

    if _version_key(new_ver) < _version_key(old_ver):
        return (
            f"downgrade attempt ({old_pkg}: {old_ver} → {new_ver}) — "
            f"would reintroduce the vulnerability, not fix it"
        )

    return None
