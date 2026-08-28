<!--
TEMPLATE — copy this file to `AGENTS.md` in a downstream project and fill in
the placeholders. It is intentionally named `AGENTS.template.md` (NOT
`AGENTS.md`) so it stays inert in this ruleset repo: Cursor auto-activates a
file literally named `AGENTS.md` (at the repo root and in subdirectories), but
ignores this template name. Placeholders are in {curly braces}.
-->

# {Project Name}

{One-line overview: what this project is and who it's for.}

## Build / Test / Run

Only the **non-obvious, project-specific** commands (skip anything a competent
developer would guess):

- **Build:** {command}
- **Test:** {command}
- **Run / dev:** {command}

## Code Style

- {Language/formatter/linter conventions specific to this repo}
- {Naming, import, or file-layout conventions worth stating}

## Architecture

- {High-level components / services and how they fit together}
- {Key directories and what lives where}
- {Runtime/deployment targets or constraints}

## IRL Testing

- **Required?** yes / no
- **Hardware / setup:** {devices, cables, jigs, firmware needed}
- **Put system in a testable state:** {step-by-step to reach that state}
- **Command(s) to run:** {exact commands}
- **What a pass looks like:** {expected output / observation}
- **Who does what:** {developer performs X; agent prepares / observes Y}
- **IRL-facing paths:** {code paths / globs that require IRL testing}
