# Fixtures

Small, self-contained assemblies the test harness ([scripts/test_fixtures.py](../scripts/test_fixtures.py))
builds and runs the analyzer on. Each one does something the check must notice (pointer code,
`Process.Start`, reflection by a name built at run time, a file write outside the game, a DLL named
after a trusted library) or something it must *not* flag, and the harness checks the tier, labels,
reasons and evidence the analyzer reports.

They work like antivirus test files: benign, tiny, never shipped, and written to be caught. Nothing
here is malicious or does anything when built. Network targets use the reserved `example.invalid`
domain. Fixtures are exempt from the analyzers and code-style rules that apply to `src/`, because
they contain code written to be flagged. Each file starts with a comment saying what it checks and
the result expected.

## Single-assembly fixtures

| Folder | What it checks |
|---|---|
| `classification/safe` | Everyday framework code (collections, LINQ, formatting, tasks) stays Limited access with no labels |
| `classification/unclassified` | A framework member the policy does not classify makes the mod Broad access |
| `download` | A download written next to the mod's own DLL: each part is Limited access, the pair is Broad access |
| `fail-open` | Access the analyzer cannot inspect (P/Invoke, COM by CLSID, ...): always Broad access |
| `fail-open/corrupt` | Writes an assembly with an undefined opcode, to check that undecodable IL is reported, not skipped |
| `file-access` | File access labelled by where the path comes from (mod folder, game folders, saves, elsewhere) |
| `impersonation` | Built under a trusted library's name (`0Harmony`) with other contents: the hash does not match, so it is scanned and flagged |
| `labels` | Capabilities that carry a Limited-access label of their own |
| `raw-memory/safe` | Ordinary C# the compiler lowers to `Unsafe` and `MemoryMarshal` helpers: not raw memory |
| `raw-memory/unsafe` | Pointer code: Broad access |
| `reflection` | A constant type name resolves to its capabilities; a name built at run time cannot be resolved |
| `report-markup` | Type and member names that are markup or a bidirectional override, to check the HTML report encodes them |
| `shell-open/link` | Opening a fixed web address: "Opens websites in your browser" |
| `shell-open/program` | Starting a program, or a link whose target is not fixed: Broad access |
| `il-probes` | A generator that writes hand-written-IL probes (IL the C# compiler does not emit); the harness analyzes the output and never runs it |

## Stand-ins and the mods that call them

Some checks need a game, a trusted library or a dependency. These stand-ins provide one with the
real names and signatures, and the mods next to them call it.

| Folder | What it is |
|---|---|
| `game-api/stub` | Stand-in for a game assembly, profiled into a game-API map |
| `game-api/mod`, `mod-exempt`, `mod-full`, `mod-gaps` | Mods that call the game through that map: plain calls, exempted members, a game wrapper that starts programs, and members the map has not read |
| `harmony-patch/stub` | Stand-in for Harmony's attributes and the members the cases use, allowlisted as a trusted library |
| `library-propagation/lib` | A bundled helper library that uses the network |
| `library-propagation/tools` | A trusted helper library with a member that starts a program through an override and one that builds code at run time |
| `library-propagation/mod`, `mod-exempt`, `mod-full` | Mods whose capabilities arrive only through those libraries |

## Multi-case projects

Each `.cs` file under `cases/` is built into its own assembly (`-p:Case=<name>`), because mod-level
results combine across a whole assembly and cases sharing one could change each other's results.
The expected result of each case is in the matching table in the harness.

| Project | Cases | Harness table | What the cases cover |
|---|---|---|---|
| `evasion/cases` | 94 | `EVASION` | Attempts to reach a capability without being flagged: aliased fields, interpolated paths, overlapping struct layouts, stackalloc, `MemoryMarshal`, reflection through generics and delegates, and the proven-safe shapes that must stay Limited access |
| `reflection-precision/cases` | 93 | `REFLECTION_PRECISION` | How precisely reflection is bounded: lookups on game, mod and framework types, inherited and nested members, ignore-case lookups, typed reads, expression trees |
| `game-interaction/cases` | 43 | `GAME_INTERACTION` | Harmony transpilers, observing patches, name filters, XML serialization of game types, `Process.Start` variants |
| `harmony-patch/mod/cases` | 20 | `HARMONY_PATCH` | `[HarmonyPatch]` targets: game, framework and trusted-library members, patch instances, `TargetMethod`, reverse patches |
| `embedded` | 5 payloads | `EMBEDDED` | One manifest resource each (`-p:Payload=text\|pe\|zip\|costura\|linked`): only plain text stays Limited access |

## Adding a fixture

See [docs/development.md](../docs/development.md#adding-a-fixture).
