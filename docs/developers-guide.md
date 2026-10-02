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
  or globs beside them.
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

## Python formatting and linting

`make check-fmt` also runs `ruff format --check`, and `make lint` runs
`ruff check`. Ruff is a development dependency bounded to `>=0.16.8,<0.17`,
because 0.16 reads rule names rather than codes in `pyproject.toml`'s `lint`
tables. Markdown is excluded from Ruff (`extend-exclude`), since mdtablefix
owns its formatting.
