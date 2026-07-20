"""Sub-Agent 4 — Remediation Executor (Fixer).

Public surface:
  run_fixer(package_id, *, ...)  — main entry point (auto-chained from master
                                    or triggered by the /fix API endpoint)

Everything else in this package is internal implementation.

Import is lazy — `from app.agents.fixer import run_fixer` triggers the
orchestrator import only when actually resolved. Lets us build submodules
bottom-up without cyclic import pain during construction.
"""


def __getattr__(name):  # PEP 562 lazy module attribute
    if name == "run_fixer":
        from .orchestrator import run_fixer

        return run_fixer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["run_fixer"]
