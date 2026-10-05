"""Tests for the Markdown formatting wiring: Makefile, CI, and configuration.

`make fmt` and `make check-fmt` are run for real against recording stubs, so the
arguments, their order and the propagation of a tool's failing exit status are
observed rather than read from the recipe text. The workflows are parsed as YAML
and the configuration as JSON or TOML, so each assertion is scoped to the key it
is about.
"""

from __future__ import annotations

import json
import os
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
LINTER_VERSION = "0.20.0"
REQUIRED_IGNORES = (
    "**/.venv/**",
    ".node_modules/**",
    "**/node_modules/**",
    "**/target/**",
    ".terraform/**",
    ".uv-cache/**",
    "CRUSH.md",
    ".vtcode/**",
    "memories/**",
)
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


LONG_PARAGRAPH = (
    "This paragraph is deliberately written as a single line that runs well past "
    "the eighty column wrap limit, so that the formatter must rewrite it and the "
    "check must refuse it until it has been rewritten.\n"
)


def _real_tool(name: str) -> str:
    """Return the path of a real tool, or skip when it is not installed.

    CI installs each tool before the tests run, so there a missing tool is a
    failure, never a skip that would let these tests silently stop running.
    """
    found = shutil.which(name)
    if found is None and os.environ.get("CI"):
        pytest.fail(f"{name} must be installed in CI to run the end-to-end tests")
    if found is None:
        pytest.skip(f"{name} is not installed")
    return found


def _real_linter(tmp_path: Path) -> Path:
    """Return a real markdownlint-cli2: an installed one, or a pinned one via npx.

    The workflow gate for this repository forbids installing the linter from a
    shell step, so CI has none installed. A wrapper then runs the pinned release
    through npx, which the runner provides. With neither, the test skips locally
    and fails under `CI`.
    """
    found = shutil.which("markdownlint-cli2")
    if found is not None:
        return Path(found)
    npx = shutil.which("npx")
    if npx is None:
        return Path(_real_tool("markdownlint-cli2"))
    wrapper = tmp_path / "markdownlint-cli2"
    wrapper.write_text(
        f'#!/bin/sh\nexec "{npx}" --yes markdownlint-cli2@{LINTER_VERSION} "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper


def _git(repo: Path, *args: str) -> None:
    """Run Git in `repo` with the ambient Git environment cleared."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    git = shutil.which("git")
    assert git, "git must be installed to run these tests"
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        [git, *args], cwd=repo, env=env, check=True, capture_output=True, timeout=60
    )


def _markdown_repo(tmp_path: Path) -> Path:
    """Build a Git repository with one unformatted Markdown file in each state.

    `tracked.md` is staged, `untracked.md` is neither staged nor ignored, and
    `ignored.md` is covered by `.gitignore`. All three hold the same long line,
    and `ignored.md` also has extra blank lines, which `markdownlint-cli2 --fix`
    removes, so a linter that reaches it can be seen to have rewritten it. The
    repository's own markdownlint configuration is copied in, since whether the
    linter honours `.gitignore` is decided there.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(ROOT / "Makefile", repo / "Makefile")
    (repo / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
    shutil.copy(ROOT / ".markdownlint-cli2.jsonc", repo / ".markdownlint-cli2.jsonc")
    for name in ("tracked.md", "untracked.md"):
        (repo / name).write_text(f"# Title\n\n{LONG_PARAGRAPH}", encoding="utf-8")
    (repo / "ignored.md").write_text(
        f"# Title\n\n\n\n{LONG_PARAGRAPH}", encoding="utf-8"
    )
    _git(repo, "init", "--quiet")
    _git(
        repo, "add", ".gitignore", ".markdownlint-cli2.jsonc", "Makefile", "tracked.md"
    )
    return repo


def _make_in(
    repo: Path, target: str, tmp_path: Path, *, real_linter: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run `make <target>` with real ruff and mdtablefix.

    The Markdown linter is a no-op stub unless `real_linter` is set, in which
    case the real `markdownlint-cli2` runs and the ambient `PATH` is kept so its
    runtime is found.
    """
    mdtablefix = _real_tool("mdtablefix")
    ruff = shutil.which("ruff")
    assert ruff, "ruff must be installed to run these tests"
    if real_linter:
        linter = _real_linter(tmp_path)
    else:
        linter = tmp_path / "markdownlint-cli2"
        linter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        linter.chmod(0o755)
    make = shutil.which("make")
    assert make, "make must be installed to run these tests"
    path = os.pathsep.join(
        sorted({
            str(Path(mdtablefix).parent),
            str(Path(ruff).parent),
            "/usr/bin",
            "/bin",
        })
    )
    if real_linter:
        path = os.environ["PATH"]
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        [make, "--no-print-directory", f"MDLINT={linter}", target],
        cwd=repo,
        env={"PATH": path, "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


@pytest.mark.parametrize("name", ["tracked.md", "untracked.md"])
def test_check_fmt_refuses_an_unformatted_eligible_file(
    tmp_path: Path, name: str
) -> None:
    """`make check-fmt` fails for an unformatted tracked or untracked Markdown file."""
    repo = _markdown_repo(tmp_path)
    for other in {"tracked.md", "untracked.md"} - {name}:
        (repo / other).write_text("# Title\n", encoding="utf-8")

    result = _make_in(repo, "check-fmt", tmp_path)

    assert result.returncode != 0, f"{name} was unformatted but check-fmt passed"


def test_check_fmt_ignores_an_unformatted_ignored_file(tmp_path: Path) -> None:
    """Git-ignored Markdown is not selected, so it cannot fail the check."""
    repo = _markdown_repo(tmp_path)
    for name in ("tracked.md", "untracked.md"):
        (repo / name).write_text("# Title\n", encoding="utf-8")

    result = _make_in(repo, "check-fmt", tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr


def test_fmt_rewrites_eligible_files_and_leaves_ignored_ones_alone(
    tmp_path: Path,
) -> None:
    """`make fmt` wraps tracked and untracked files, after which the check passes.

    The real linter runs, so an ignored file the linter would otherwise reach
    with `--fix` is seen to be left alone.
    """
    repo = _markdown_repo(tmp_path)
    ignored_before = (repo / "ignored.md").read_text(encoding="utf-8")

    result = _make_in(repo, "fmt", tmp_path, real_linter=True)

    assert result.returncode == 0, result.stdout + result.stderr
    for name in ("tracked.md", "untracked.md"):
        lines = (repo / name).read_text(encoding="utf-8").splitlines()
        assert max(len(line) for line in lines) <= 80, f"{name} was not wrapped"
    assert (repo / "ignored.md").read_text(encoding="utf-8") == ignored_before
    assert _make_in(repo, "check-fmt", tmp_path).returncode == 0


def _workflow(name: str) -> dict[typ.Any, typ.Any]:
    """Return the parsed workflow file."""
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


def _steps(workflow: dict[typ.Any, typ.Any], job: str) -> list[dict[str, typ.Any]]:
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


def _lint_workflow() -> dict[typ.Any, typ.Any]:
    """Return the parsed Markdown lint workflow."""
    return _workflow("markdownlint.yml")


def test_markdown_lint_covers_every_markdown_file_through_with_globs() -> None:
    """The lint action's `with.globs` is `**/*.md`; an `env` key would not set it."""
    steps = _steps(_lint_workflow(), "markdownlint")
    lint = steps[_index_of(steps, LINT_ACTION)]

    assert lint["with"]["globs"] == "**/*.md"


def test_markdown_lint_action_is_pinned_to_a_commit() -> None:
    """The lint action is referenced by a full commit SHA, so a moved tag is inert."""
    steps = _steps(_lint_workflow(), "markdownlint")
    uses = steps[_index_of(steps, LINT_ACTION)]["uses"]

    assert re.fullmatch(re.escape(LINT_ACTION) + r"[0-9a-f]{40}", uses), uses


def test_markdown_lint_runs_on_pushes_to_main_and_pull_requests() -> None:
    """Both triggers are present, and the push trigger is limited to main."""
    workflow = _lint_workflow()
    triggers = workflow["on"] if "on" in workflow else workflow[True]

    assert "pull_request" in triggers, "the lint must run on pull requests"
    assert triggers["push"] == {"branches": ["main"]}, "push must be limited to main"


def test_markdown_lint_has_a_timeout_and_cancels_superseded_pull_requests() -> None:
    """The lint job has a ceiling, and only pull request runs are cancelled."""
    workflow = _lint_workflow()
    timeout = workflow["jobs"]["markdownlint"]["timeout-minutes"]
    cancel = str(workflow["concurrency"]["cancel-in-progress"])

    assert isinstance(timeout, int)
    assert timeout > 0, "the timeout must be positive"
    assert "github.event_name == 'pull_request'" in cancel, cancel
    assert "github.event.pull_request.number" in workflow["concurrency"]["group"]


def _config() -> dict[str, typ.Any]:
    """Return the parsed markdownlint configuration."""
    return json.loads((ROOT / ".markdownlint-cli2.jsonc").read_text())


def test_markdownlint_config_keeps_the_canonical_rules() -> None:
    """`.markdownlint-cli2.jsonc` keeps every canonical rule setting."""
    config = _config()["config"]

    for rule, settings in CANONICAL_CONFIG.items():
        assert config.get(rule) == settings, f"{rule} differs from the estate setting"


def test_markdownlint_config_keeps_every_required_ignore() -> None:
    """Each ignore pattern stays, so dependency and scratch trees are not linted."""
    ignores = set(_config()["ignores"])

    missing = sorted(set(REQUIRED_IGNORES) - ignores)
    assert not missing, f"required ignore patterns are missing: {missing}"


def test_markdownlint_config_honours_gitignore() -> None:
    """The linter skips Git-ignored files, so `make fmt` cannot rewrite them."""
    assert _config()["gitignore"] is True


def test_ruff_leaves_markdown_to_mdtablefix_and_is_bounded() -> None:
    """Ruff excludes Markdown, and its constraint reaches 0.16.8 but stops at 0.17."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())

    assert "*.md" in pyproject["tool"]["ruff"]["extend-exclude"]
    assert "ruff>=0.16.8,<0.17" in pyproject["dependency-groups"]["dev"]
