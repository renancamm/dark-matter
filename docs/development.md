# Development

How the repository is laid out, how to build and test it, and how to change a detection rule.

## Layout

| Path | Purpose |
|---|---|
| `policy/policy.jsonc` | capability rules, labels, tiers, Broad-access triggers and their groups, path sources |
| `src/DarkMatter/` | the analyzer, `darkmatter` |
| `src/DarkMatter/Analysis/` | single pass over each assembly: IL decoding, capabilities, reflection, calls, fields, path sources |
| `src/DarkMatter/Evaluation/` | file-path origin tracing, reach propagation, tiers and labels per mod, the game-API map, trusted-library profiles |
| `src/DarkMatter/Cli/` | command line: options, inputs, text and JSON output |
| `src/DarkMatter/Policy.cs` | policy loading, validation and rule matching |
| `src/DarkMatter.Pipeline/` | the pipeline, `darkmatter-pipeline` |
| `src/DarkMatter.Pipeline/Scan/` | `scan`: release selection, stored results by release and scan key, the analyzer process, changes, text output |
| `src/DarkMatter.Pipeline/Report/` | `report`: the HTML report |
| `src/DarkMatter.Pipeline/Extract/` | `extract`: archive detection, entry name checks, zip and tar extraction into a claimed tree, the manifest |
| `src/DarkMatter.Pipeline/Index/` | the index snapshot, archives verified against their stamp, `build-allowlist`, HTTPS with retries |
| `src/DarkMatter.Pipeline/Results/` | `compare-results`, `rank-unclassified` |
| `fixtures/` | minimal assemblies for each case, see [fixtures/README.md](../fixtures/README.md) |
| `scripts/test_fixtures.py` | builds the fixtures and checks the analyzer, extraction and scans against them |
| `scripts/format.sh` | checks or fixes formatting with `dotnet format` |
| `scripts/legacy/` | the old GitHub-API download path, a fallback until `scan` has downloaded from the live index once |
| `docs/` | user and reference documentation |

`DarkMatter.slnx` contains the analyzer, the pipeline and every fixture; `global.json` pins the
.NET 10 SDK band.

## Building

```sh
dotnet build src/DarkMatter -c Release -o out
dotnet build src/DarkMatter.Pipeline -c Release -o out
```

The policy is embedded in `darkmatter.dll` at build time, so rebuild after every policy edit.

Code under `src/` builds with nullable reference types, the recommended .NET analyzers and
code-style enforcement, with warnings treated as errors (`src/Directory.Build.props`). Fixtures are
exempt: they contain code written to be flagged. Formatting follows `.editorconfig`.
`scripts/format.sh` runs `dotnet format` on both projects:

```sh
scripts/format.sh                # check whitespace, code style and analyzers; changes nothing
scripts/format.sh --fix          # apply the fixes
scripts/format.sh --whitespace   # whitespace only (needs no build host)
```

It exits 1 when there is something to fix and 3 when `dotnet format` cannot run.

## Testing

```sh
python3 scripts/test_fixtures.py
```

Builds the analyzer and every fixture and checks tiers, labels, evidence, allowlist handling,
the game-API map, fail-closed behaviour, policy validation, archive extraction safety
(`darkmatter-pipeline extract` on hostile archives), scans of a small offline snapshot (release
selection, stored results, changes, archives that do not match their stamp), the HTML report's
encoding, and the result tools. It needs the .NET 10 SDK and Python 3.9 or later (standard library
only), and no network.

Everything is built in one incremental MSBuild run into each project's own `bin/` and `obj/`, so
a run after a small change recompiles only what changed (`--rebuild` starts from scratch). The
checks are grouped and the groups run in parallel. While working on one area, run only its
groups, and run everything before committing:

```sh
python3 scripts/test_fixtures.py --list                     # group names
python3 scripts/test_fixtures.py --only evasion,harmony-patch
```

A filtered run ends by saying how many groups it skipped. The harness turns off the C# compiler
server (`UseSharedCompilation=false`). In sandboxes that block its pipe, every compile otherwise
waits for the connection to time out. `--keep` leaves the temporary directory (profiles, results,
test archives) in place for inspection.

## Changing a detection rule

The rules live in [policy/policy.jsonc](../policy/policy.jsonc); the analyzer validates the file
on load.

1. **Write a fixture first** that shows the gap: a case the check misses, or flags wrongly. See
   [Adding a fixture](#adding-a-fixture).
2. **Change the policy or the analyzer.** Every capability must be assigned to exactly one of
   `broadAccess` (in one of its groups), `labels`, `fileAccess.kinds` or `informational`, or the
   policy fails validation.
3. **Bump `"version"`** in the policy whenever the change can alter a result, and add an entry to
   [policy-changelog.md](policy-changelog.md) saying what changed and which results can move.
4. **Run the full suite.**
5. **If a gap cannot be closed**, describe it in [known-gaps.md](known-gaps.md), and make sure the
   case fails toward Broad access in the meantime.

Two rules hold for every change:

- **Never run mod code.** Assemblies are read as metadata and IL with `System.Reflection.Metadata`;
  nothing is loaded into an executing context.
- **Fail closed.** A blind spot (IL that does not decode, reflection that cannot be traced, native
  code, a file that cannot be read) must move a mod *up* to Broad access, never down. An evasion
  attempt should make a mod look more dangerous, not less.

## Adding a fixture

Fixtures are described in [fixtures/README.md](../fixtures/README.md). Keep each one minimal and
benign, start it with a comment saying what it checks and the result expected, and use
`example.invalid` for any network target.

- **A case in an existing multi-case project** (`evasion`, `harmony-patch/mod`,
  `reflection-precision`, `game-interaction`, `embedded`): add the `.cs` file under `cases/`, then
  the case and its expected result to the project's table in the harness (`EVASION`,
  `HARMONY_PATCH`, ...).
- **A hand-written-IL probe** (IL the C# compiler does not emit): add its writer to
  `fixtures/il-probes/Program.cs` and its expectation to `IL_PROBES`. The harness only analyzes
  the generated assemblies; nothing generated is run.
- **A check in an existing group:** add it to that group's `g_<group>()` function. If it uses a new
  single-assembly fixture, add the fixture's folder to the group's row in `GROUPS`, or it is not
  built under `--only`.
- **A new group:** write `g_<name>()`, add a row to `GROUPS` (name, function, single-assembly
  fixtures, multi-case projects), and add any new fixture project to `DarkMatter.slnx`.
- **A new multi-case project:** add it to `MULTI` (project file, property, assembly prefix, cases
  table), set `<AssemblyName>Prefix.$(Case)</AssemblyName>` and a default `Case`, and, if it
  references other projects, remove `Case`, `OutDir` and `IntermediateOutputPath` from what it
  passes them (`GlobalPropertiesToRemove`, as the existing ones do).

After changing the harness, check that a deliberately broken expectation shows `FAIL` and makes
the run exit 1.
