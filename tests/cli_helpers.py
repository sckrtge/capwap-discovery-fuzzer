"""Shared helpers for CLI tests.

Rich wraps its error panels to the reported terminal width, so a message like
``--ap-mac must be hex`` can come back split across lines when the width is
narrow - which is what CI (narrow/unknown width) does and a local wide terminal
does not.  Asserting on raw output therefore produces tests that pass locally
and fail in CI.  Both helpers below exist to prevent that:

* :func:`invoke_cli` pins COLUMNS/LINES so rendering is deterministic.
* :func:`flat` strips ANSI colour and collapses whitespace, so a phrase that was
  wrapped is still matchable.
"""

from __future__ import annotations

import re

from typer.testing import CliRunner

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

#: Wide enough that rich never wraps these short error messages.
TERMINAL_ENV = {"COLUMNS": "200", "LINES": "60"}


def invoke_cli(app, args, env: dict | None = None):
    """Invoke a Typer app with a deterministic, wide terminal."""
    merged = dict(TERMINAL_ENV)
    if env:
        merged.update(env)
    return CliRunner().invoke(app, list(args), env=merged)


def flat(text: str) -> str:
    """Strip ANSI escapes and collapse whitespace (unwraps rich's line breaks)."""
    return re.sub(r"\s+", " ", _ANSI_RE.sub("", text)).strip()
