# Developers' guide

This guide records how the project's development tooling is wired, for people
changing the code or its documentation. User-facing behaviour is in the
[users' guide](users-guide.md), and prose conventions are in the
[documentation style guide](documentation-style-guide.md).

## Markdown formatting

Markdown follows the estate's `markdown-formatting-baseline` rule.

- `make fmt` rewrites Markdown with
  `mdtablefix --in-place --git --include-untracked --wrap --renumber --breaks
  --ellipsis --fences`,
  then runs `markdownlint-cli2 --fix "**/*.md"`.
- `make check-fmt` runs the same `mdtablefix` command with `--check` in place of
  `--in-place`, and fails when any file would change. It does not run the
  linter's fixes.
- `--git --include-untracked` selects the Markdown files Git tracks plus the
  untracked files Git does not ignore, so a new document is checked before it
  is staged.
- `.markdownlint-cli2.jsonc` carries the canonical markdownlint configuration.
  Keep its `config` entries and `ignores` globs; add repository-specific rules
  or globs beside them. `"gitignore": true` makes markdownlint-cli2 skip
  Git-ignored files, which it does not do by default, so `make fmt`'s `--fix`
  cannot rewrite a file mdtablefix left alone.
- CI installs mdtablefix 0.6.1 with the shared `install-mdtablefix` action
  before `make check-fmt`, and the `markdownlint` workflow lints `**/*.md` with
  the pinned `DavidAnson/markdownlint-cli2-action`.

Install mdtablefix 0.6.1 or later locally with
`cargo binstall --no-confirm mdtablefix@0.6.1`, or
`cargo install --locked mdtablefix@0.6.1`. Install markdownlint-cli2 with
`bun add --global markdownlint-cli2` or
`npm install --global markdownlint-cli2`. A missing tool stops `make` with an
error that names it.

`concordat artefact rule run markdown-formatting-baseline` audits this wiring.

`tests/test_markdown_wiring.py` holds the wiring. It runs the real `make fmt`
and `make check-fmt` against recording stubs, so the arguments, the order and
the propagation of a failing tool's exit status are observed. It also parses
the workflows as YAML to require an `install-mdtablefix` step at 0.6.1 or later
before `make check-fmt` and `globs: '**/*.md'` under the lint action's `with:`,
and checks the canonical rule settings in `.markdownlint-cli2.jsonc` and Ruff's
Markdown exclusion and version bound. PyYAML is a development dependency for
that parsing.

It also runs the real `mdtablefix` against a scratch Git repository with an
unformatted Markdown file that is tracked, one that is untracked, and one that
is ignored, to show that `make check-fmt` refuses the first two and not the
third, and that `make fmt` wraps the first two and leaves the third alone.
Those tests are skipped locally when `mdtablefix` is not installed, and fail
when `CI` is set, so CI cannot stop running them. The `make fmt` test also runs
the real `markdownlint-cli2` with the repository's own configuration: an
installed one if there is one, otherwise release 0.20.0 through `npx`. CI
installs none, because the estate baseline rule forbids installing the linter
from a CI shell step, so it takes the `npx` path.

## Python formatting and linting

`make check-fmt` also runs `ruff format --check`, and `make lint` runs
`ruff check`. Ruff is a development dependency bounded to `>=0.16.8,<0.17`,
because 0.16 reads rule names rather than codes in `pyproject.toml`'s `lint`
tables. Markdown is excluded from Ruff (`extend-exclude`), since mdtablefix
owns its formatting.
