"""Tests for the Markdown formatting wiring: Makefile, CI, and configuration.

`make fmt` and `make check-fmt` are run for real against recording stubs, so the
arguments, their order and the propagation of a tool's failing exit status are
observed rather than read from the recipe text. The workflows are parsed as YAML
and the configuration as JSON or TOML, so each assertion is scoped to the key it
is about.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import tomllib
import typing as typ
from pathlib import Path

import pytest
import yaml

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ROOT = Path(__file__).resolve().parents[1]
SHARED_FLAGS = (
    "--git --include-untracked --wrap --renumber --breaks --ellipsis --fences"
)
INSTALL_ACTION = "leynos/shared-actions/.github/actions/install-mdtablefix@"
LINT_ACTION = "DavidAnson/markdownlint-cli2-action@"
MINIMUM_VERSION = (0, 6, 1)
CANONICAL_CONFIG: dict[str, typ.Any] = {
    "MD004": {"style": "dash"},
    "MD010": {"code_blocks": False},
    "MD013": {
        "line_length": 80,
        "code_block_line_length": 120,
        "tables": False,
        "headings": False,
    },
    "MD029": {"style": "ordered"},
}


def _stub_script(tool: str, exit_code: int) -> str:
    """Return a script that records its name and arguments, then exits."""
    return f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> "$LOG"\nexit {exit_code}\n'


def _run_make(
    tmp_path: Path,
    target: str,
    *,
    failing: str | None = None,
    without: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run `make <target>` in a scratch copy with a stub-only `PATH`.

    Every tool the target calls is a recording stub appending to `$LOG`. The tool
    named by `failing` exits non-zero, and the one named by `without` is not
    installed. Returns the result and the recorded calls.
    """
    make = shutil.which("make")
    assert make, "make must be installed to run these tests"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "make").symlink_to(make)
    for tool in ("ruff", "mdtablefix", "markdownlint-cli2"):
        if tool == without:
            continue
        stub = bin_dir / tool
        stub.write_text(_stub_script(tool, int(tool == failing)), encoding="utf-8")
        stub.chmod(0o755)
    shutil.copy(ROOT / "Makefile", tmp_path / "Makefile")
    log = tmp_path / "log"
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed argv, no shell
        [str(bin_dir / "make"), "--no-print-directory", target],
        cwd=tmp_path,
        env={"PATH": str(bin_dir), "LOG": str(log)},
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def test_check_fmt_runs_the_ruff_check_then_mdtablefix_in_check_mode(
    tmp_path: Path,
) -> None:
    """`make check-fmt` checks Python, then Markdown, with every flag."""
    result, calls = _run_make(tmp_path, "check-fmt")

    assert result.returncode == 0, result.stderr
    assert calls == ["ruff format --check", f"mdtablefix --check {SHARED_FLAGS}"]


def test_fmt_rewrites_then_runs_the_linter_with_fix_last(tmp_path: Path) -> None:
    """`make fmt` rewrites Python and Markdown, then runs the linter with `--fix`."""
    result, calls = _run_make(tmp_path, "fmt")

    assert result.returncode == 0, result.stderr
    assert calls == [
        "ruff format",
        "ruff check --select I --fix",
        f"mdtablefix --in-place {SHARED_FLAGS}",
        "markdownlint-cli2 --fix **/*.md",
    ]


@pytest.mark.parametrize(
    ("target", "failing"),
    [
        ("check-fmt", "mdtablefix"),
        ("check-fmt", "ruff"),
        ("fmt", "mdtablefix"),
        ("fmt", "markdownlint-cli2"),
        ("fmt", "ruff"),
    ],
)
def test_a_failing_tool_fails_the_target(
    tmp_path: Path, target: str, failing: str
) -> None:
    """A tool's failing exit status reaches Make; it is not swallowed."""
    result, _ = _run_make(tmp_path, target, failing=failing)

    assert result.returncode != 0, f"a failing {failing} did not fail make {target}"


def test_a_failing_mdtablefix_stops_fmt_before_the_linter_runs(tmp_path: Path) -> None:
    """The linter must not run, and so cannot mask, a failed rewrite."""
    _, calls = _run_make(tmp_path, "fmt", failing="mdtablefix")

    assert not any(call.startswith("markdownlint-cli2") for call in calls), calls


def test_a_missing_linter_fails_fmt_naming_it(tmp_path: Path) -> None:
    """`make fmt` stops and names `markdownlint-cli2` when it is not installed."""
    result, calls = _run_make(tmp_path, "fmt", without="markdownlint-cli2")

    assert result.returncode != 0, "a missing linter did not fail make fmt"
    assert "'markdownlint-cli2' is required, but not installed" in result.stderr
    assert not calls, f"a tool ran before the missing linter was reported: {calls}"


def _workflow(name: str) -> dict[str, typ.Any]:
    """Return the parsed workflow file."""
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


def _steps(workflow: dict[str, typ.Any], job: str) -> list[dict[str, typ.Any]]:
    """Return the steps of the named job, in order."""
    return workflow["jobs"][job]["steps"]


def _index_of(steps: cabc.Sequence[dict[str, typ.Any]], predicate: str) -> int:
    """Return the index of the first step whose `uses` or `run` matches."""
    for index, step in enumerate(steps):
        if predicate in step.get("uses", "") or step.get("run", "") == predicate:
            return index
    message = f"no step matches {predicate!r}"
    raise AssertionError(message)


def _version(text: str) -> tuple[int, ...]:
    """Parse a dotted numeric version."""
    return tuple(int(part) for part in text.split("."))


def test_ci_installs_mdtablefix_at_the_minimum_before_check_fmt() -> None:
    """The job running `make check-fmt` installs mdtablefix 0.6.1+ just before it."""
    steps = _steps(_workflow("ci.yml"), "lint-test")
    install = _index_of(steps, INSTALL_ACTION)
    check = _index_of(steps, "make check-fmt")

    assert install < check, "mdtablefix must be installed before make check-fmt"
    pinned = _version(str(steps[install]["with"]["version"]))
    assert pinned >= MINIMUM_VERSION, f"mdtablefix {pinned} is below the minimum"


def test_the_install_action_is_pinned_to_a_commit() -> None:
    """The shared installer is referenced by a full commit SHA, not a tag."""
    steps = _steps(_workflow("ci.yml"), "lint-test")
    uses = " ".join(steps[_index_of(steps, INSTALL_ACTION)]["uses"].split())

    assert re.fullmatch(re.escape(INSTALL_ACTION) + r"[0-9a-f]{40}", uses), uses


def test_markdown_lint_covers_every_markdown_file_through_with_globs() -> None:
    """The lint action's `with.globs` is `**/*.md`; an `env` key would not set it."""
    steps = _steps(_workflow("markdownlint.yml"), "markdownlint")
    lint = steps[_index_of(steps, LINT_ACTION)]

    assert lint["with"]["globs"] == "**/*.md"


def test_markdown_lint_workflow_has_a_timeout_and_cancels_superseded_runs() -> None:
    """The lint job has a ceiling, and a newer push cancels an older PR run."""
    workflow = _workflow("markdownlint.yml")

    assert isinstance(workflow["jobs"]["markdownlint"]["timeout-minutes"], int)
    assert "cancel-in-progress" in workflow["concurrency"], "no concurrency control"


def test_markdownlint_config_keeps_the_canonical_rules() -> None:
    """`.markdownlint-cli2.jsonc` keeps every canonical rule setting."""
    config = json.loads((ROOT / ".markdownlint-cli2.jsonc").read_text())["config"]

    for rule, settings in CANONICAL_CONFIG.items():
        assert config.get(rule) == settings, f"{rule} differs from the estate setting"


def test_ruff_leaves_markdown_to_mdtablefix_and_is_bounded() -> None:
    """Ruff excludes Markdown, and its constraint reaches 0.16.8 but stops at 0.17."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())

    assert "*.md" in pyproject["tool"]["ruff"]["extend-exclude"]
    assert "ruff>=0.16.8,<0.17" in pyproject["dependency-groups"]["dev"]
