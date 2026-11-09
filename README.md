# Dark Matter

Static access analysis for Kitten Space Agency mods. Dark Matter reads a mod's compiled .NET
assemblies, without loading or running them, and places the mod in one of three access tiers
with a list of what it can do, in the way an app store lists permissions.

> **Status: prototype.** Results are only as complete as the policy's rules. A missing label
> means the check found nothing, not that nothing is there. Design rule: **every blind spot
> fails upward, to Full access, never to Limited access or No code.**

## Tiers

A tier states what a mod can do, as far as the check can account for it. It is not a judgement
of whether the mod is harmful, and it says what the mod *can* do, not what it does.

| Tier | Shown to players | Meaning |
|---|---|---|
| **No code** | Only adds content. It can't run programs. | Ships no code files: parts, planets, textures, sounds. |
| **Limited access** | It can only do what's listed. | Ships code, and everything it can run was looked at. The labels are the complete list. |
| **Full access** | It can do anything a program on your computer can. | Something in the mod can reach beyond what the check can list, or the check could not look at all. The labels are what it saw, not a complete list. |

A Full-access result says why, in one or more groups. Every group with a reason is listed, so a
mod whose reasons move from one group to another between releases stands out even though its
tier stays the same.

| Group | Shown to players | For example |
|---|---|---|
| **Deep game access** | Works with the game's code and memory directly, in ways the check can't follow all the way. | direct memory access, transpilers on the game's code |
| **System access** | Uses features that can reach anything on your computer. | native code, starting programs, loading code at run time |
| **Couldn't be fully checked** | Part of the mod couldn't be inspected. | an unreadable file, a script or installer, an embedded archive |

**The groups explain the tier; they are not a scale.** The claim is the tier: Full access. Deep
game access means the check's blind spots for this mod are of a kind ordinary modding has, not
that the mod stays inside the game. Code the check cannot follow can still do anything, and a
determined author who knows the rules can aim for that group alone. Couldn't be fully checked
means the check does not know what a part does, not that it does anything; it is often a
packaging problem the author can fix. Only Limited access says the labels are complete.

Many widely used mods are Full access (loaders, scripting bridges, physics mods, mods that use
native libraries). For those, trust rests on the author rather than on the check.

A reason reached through another member (a framework, game or trusted-library member the mod
calls, reaches by reflection or patches) is reported in that reason's group.

### Deep game access

The mod:

- reads or writes memory directly: pointer code (including pointer types in the signatures of
  members it calls, reads and writes through an address that is not a managed reference, and a
  by-reference argument, local or returned reference that is not one), `Marshal`, `Unsafe`,
  `NativeMemory`, `MemoryMarshal`, vector loads and stores at an unchecked offset. The game's API
  is pointer-heavy, so ordinary mods do this. Policy 9 does not yet tell an address the game hands
  over from one the mod makes up (see "Known gaps")
- uses reflection the check traces only to the game's or its own code: a member of the run-time
  type of an object whose declared type is a game or mod type (`vehicle.GetType().GetField(...)`:
  that type or one derived from it), a type found by a name built at run time in a game or mod
  assembly (`typeof(KSA.Program).Assembly.GetType(name)`), or a member from a lookup on a game or
  mod type (`GetMethods()`, ...) after the array or list was passed to code the check does not
  follow. Ordinary modding reads game internals this way; the check knows which code it is in but
  not exactly which member, so the labels may miss what that member does
- rewrites the game's code, and only the game's, with a Harmony transpiler (`CodeInstruction`,
  `CodeMatch`, `CodeMatcher`, `Transpilers`, an `ILGenerator`'s labels and locals; any other target
  is system access, see below). Harmony compiles the patched game method
  from the instructions the transpiler returns, which the check does not read as a whole: what the
  new instructions name is traced (see System access), `OpCodes.Calli` is native code, but
  what the game method's own instructions do once rearranged is not followed. Ordinary modding
  does this to change the game's behaviour inside a method
- reads or writes XML with `XmlSerializer` for a type: it creates objects of that type and of the
  types its fields, properties and attributes name, and sets their members, which the check does
  not follow (the type is chosen in the mod's code, not by the XML). This holds even when the check
  did not trace the type (a generic `typeof(T)`), which is then not bounded to the game's or the
  mod's code: see "XmlSerializer is deep game access" under Known gaps

### System access

The mod:

- runs native code: P/Invoke, `calli`, mixed-mode or precompiled (ReadyToRun) assemblies, native binaries, `NativeLibrary`
- ships a native program or library: a file without .NET metadata, or an ELF or Mach-O image
- loads or builds code at run time: `Assembly.Load*`, `Reflection.Emit` (`DynamicMethod`,
  `ILGenerator.Emit`, `AssemblyBuilder`), compiled expression trees (unless the tree is built only
  from members the check traced, see below), Roslyn, `MetadataUpdater.ApplyUpdate`, an
  `[XmlSerializerAssembly]` attribute. A Harmony transpiler on the game's code is not code
  generation (see Deep game access)
- rewrites code other than the game's with a Harmony transpiler (policy 12): a transpiler whose
  target is a framework member (`string.Concat`), a trusted library's, one of the mod's own, a
  member of code that was not analyzed, a game type known only up to its derived types, or a target
  the check cannot place (an untraced `TargetMethod` result or `Harmony.Patch` original, any
  `PatchProcessor.AddTranspiler`, a reverse patch's original when the mod uses the transpiler
  helpers). Deep game access covers a transpiler only because what it can change is bounded to the game
  method it rewrites
- starts other programs: `Process.Start`, except opening a fixed web address, or a folder the
  same method has just created with `Directory.CreateDirectory` in its own or the game's folders
  (whose name has no extension)
- uses a deserializer that can create any type (`BinaryFormatter`, `NetDataContractSerializer`, ...)
- calls members by name at run time (`dynamic`, late binding)
- uses reflection the check cannot trace to the game's or its own code: a type name built at run
  time (outside `typeof(GameType).Assembly.GetType(...)`), or invoking, creating, reading or
  writing a member or type that does not come from a constant name, `typeof`, or a lookup on one
  (for example one found with `GetType()` on an object of an unknown type, or in a framework
  assembly's `GetTypes()`), an array or list of members into which something untraced was put,
  a `Type` or member parameter of a method that code outside the mod can call, an
  `[UnsafeAccessor]`, or starts a COM component. Harmony patch targets count as reflection: a
  `TargetMethod` or `TargetMethods` result or `Harmony.Patch` original that is not traced (an
  array, list or `yield return` iterator of traced members is traced), a Harmony attribute
  type defined by the mod (its constructor sets the target in code), and the operand of an
  instruction a transpiler makes or changes (`new CodeInstruction(op, operand)`, `operand = ...`,
  `CodeMatcher.SetOperandAndAdvance`, ...) that is neither traced nor an inert value (a number, a
  string, a label, a local, or another instruction's operand)
- reaches by reflection, or patches with Harmony, a framework, game or trusted-library member that
  can reach any of the above: a prefix sees and can change the patched method's arguments, so a patch on
  `Process.Start`, or on a game method that starts whatever its caller names, starts programs. A
  patch class whose patch methods can only observe (a prefix, postfix or finalizer that returns
  nothing and takes only strings, numbers, `__originalMethod` or `__state`) passes nothing on from a
  game or trusted-library target; a transpiler on a game member that a policy exemption names gets
  the exempted capability back (the exemption assumes the game's own code runs there), and one on a
  game member that opens a fixed web address or a folder starts programs (policy 12)
- calls a trusted-library or game member that can reach any of the above, unless the policy
  exempts that member for that capability (each exemption is listed with its reason in
  [policy/policy.jsonc](policy/policy.jsonc); for example Harmony's patching API, whose code
  generation and native code are how patching works, and the game's own native bindings)
- connects to the internet and changes files in its own or the game's folders, where the mod
  loader finds code (any DLL in a mod folder, `mod.toml`, `*.deps.json`, the game's mod
  manifest), or in places the check cannot place outside them. The check does not prove the
  written bytes came from the network; the pair is enough to install code for the next launch

### Couldn't be fully checked

The mod:

- contains code, a file or an archive the check cannot read, or ships a script or installer; an
  archive counts as unreadable when extraction refused any of its entries (absolute paths, `..`,
  links, devices, names Windows does not allow, two names that are one file ignoring case)
- embeds a program, library or archive as a resource: recognized by its leading bytes (PE,
  ELF, Mach-O, zip, gzip, 7z, RAR, xz, zstd, LZ4, bzip2, cabinet, tar), by a PE header anywhere
  in the resource, or by a bundler's name (Costura.Fody's `costura.*.dll.compressed`, `*.dll`);
  a resource linked from a separate file counts too
- reads its own embedded data and writes files where the game loads code from, or to places the
  check cannot place outside the game's code folders: an embedded binary the check cannot
  recognize (compressed or encrypted) has to be written out this way
- ships a file named like a .NET, game or trusted-library assembly that is not the trusted copy
  itself: references to that name load the other assembly, not the file the check read
- uses a part of .NET the policy does not classify (every framework member must match a
  capability rule or the policy's `safe` list), directly or by reflection on a framework type
- calls code that was not analyzed: an assembly that is not one of the mod's files, a trusted
  library, the game, or the .NET framework (for example another mod it depends on, or a game
  assembly the current game no longer ships), or a trusted library without a profile for every
  trusted version. This includes reflection on a type of such an assembly
  (`Type.GetType("Some.Type, OtherMod")`), or a type found by name that none of them has
- lists a file that was not analyzed (for example one whose hash changed after extraction)

**Labels**, shown in every tier (the complete list in Limited access, what the check saw in
Full access):

| Label | What it covers |
|---|---|
| Changes how the game works | patches game code (Harmony, including `[HarmonyPatch]` attributes, MonoMod, Mono.Cecil) |
| Connects to the internet | any network or pipe connection (not IP addresses or endpoints as values), including XML loaded from a path whose beginning the check cannot trace (it can be a web address) |
| Changes game saves | file writes traced to the game's save folder |
| Changes files in its own or the game's folders | file writes or deletes traced to the mod's folder or the game's folders, where the loader finds mod code and settings |
| Changes files outside the game | file writes or deletes not traced to the mod's or the game's folders (including through a file method taken as a delegate, or a Harmony patch on one) |
| Reads files outside the game | file reads not traced to the mod's or the game's folders |
| Reads information about you and your computer | user and computer name, environment variables, running programs, the Windows registry, the certificate store and persisted keys, the computer's network interfaces and connections |
| Changes system settings | writes to the Windows registry, permanent environment variables, the certificate store, persisted keys |
| Closes other programs | `Process.Kill` |
| Opens websites in your browser | `Process.Start` with a fixed `http(s)` address |
| Opens its own or the game's folders | `Process.Start` of a folder the same method has just created with `Directory.CreateDirectory`, traced to the mod's or the game's folders, whose name has no extension |
| Uses your clipboard | clipboard get/set |
| Uses connected devices | serial ports |

Cryptography, compression, threads, reflection on known types, locating standard folders and
process-only environment variables are recorded but carry no label and do not affect the tier.

## How it works

`darkmatter` reads each assembly once and records, per method: referenced capabilities,
reflection targets, calls, field reads and writes, and where file paths come from. Every
decision is then made from that one model, using the rules in
[policy/policy.jsonc](policy/policy.jsonc).

1. **Capabilities.** Each member reference in the IL is matched against the policy's rules;
   the most specific (longest) pattern wins.
2. **Nothing unaccounted for.** Every reference into another assembly is resolved by assembly
   name: one of the mod's own files (analyzed with it), a trusted library, the game (the game
   profile's assembly list, else the policy's `game.assemblies` patterns), or the .NET shared
   framework the tool runs on. A framework member that matches no capability or `safe` rule,
   and any reference to an assembly that is none of these, means Full access (couldn't be fully checked). Members are
   classified by the policy, not derived from the framework's code.
3. **Reflection.** Constant strings, integers and `typeof` tokens are tracked through the stack
   and locals. A type resolved from a constant (`Type.GetType("System.Net.Http.HttpClient")`)
   gets the capabilities of that type and all its members by the policy's rules. Where the type
   lives decides the rest, as for a typeof: its assembly qualifier, or for a name without one, the
   calling assembly and the core library (`Type.GetType`) or any assembly with a type of that
   name (`AccessTools.TypeByName`). Members reached on a framework type must be classified; on a
   game type they get the game-API map's capabilities of the members reached (by a constant
   member name, else the whole type); on a trusted-library type its profile; anywhere else it is
   code that was not analyzed. A type name that is not a constant at the call is unresolved and
   means Full access. Members looked up on a resolved type
   (`GetMethod`, `AccessTools.Field`, ...) carry that type, and `Invoke`, `GetValue`,
   `SetValue`, `CreateDelegate`, `Activator.CreateInstance(Type)`, Harmony patch methods,
   expression-tree factories (`Expression.Call`, `Field`, `Property`, `New`, ...) and similar
   calls must act on such a member or type, or they are Full access too. Arrays and lists from
   plural lookups (`GetMethods`, `GetProperties`, `AccessTools.GetDeclaredFields`, ...) are
   followed within the method that made them: each element (`foreach`, indexing, LINQ `First`,
   `Where`, `ToList`, ...) is a member of the looked-up type, which granted all of that type's
   capabilities, until something untraced is put into the array or list or it is passed to code
   the check does not follow. When every element is taken out by a LINQ `First`, `Single`, `Last`,
   `Any`, `All` or `Count` whose lambda the check proves requires a constant name
   (`m => m.Name == "Draw" && ...`), the lookup reaches only the members of that name. A type or member kept in a field (or an array of them), passed as
   an argument, or returned by a method of the mod is traced through every write to that field,
   every call, every `return` in the mod; a field that is also assigned something else, that
   other assemblies can assign, or whose type has fields written through reflection, a parameter
   of a method that code outside the mod can call (public on a visible type, virtual, a Harmony
   patch method, one with attributes a loader looks for, one taken as a delegate or reached by
   the mod's own reflection), and the result of a method that can be overridden, are not traced.
   A member name passed as a string parameter is traced from every call too. Harmony's
   `TargetMethods` may return an array or list of traced members or `yield return` them. A
   compiled expression tree built only from traced members (parameters, constants, conversions,
   calls, member access, constructors, assignments, blocks, lambdas) runs only those members and
   is not code generation. A member of the run-time type of an object of a declared game or mod
   type, and a type of a game or mod assembly found by a name built at run time, are bounded:
   deep game access, not system access. Tracking resets at every branch target and exception handler,
   except that a local's type or member is traced from all its stores (and when they differ, as
   one of them).
4. **Libraries by hash, not by name.** A file is trusted only if its SHA-256 is on the
   allowlist. A file that uses a trusted library's assembly name with an unknown hash is
   analyzed as mod code and flagged. Every other bundled file is analyzed with the mod, so a
   capability inside a bundled library is part of the mod's result.
5. **Trusted-library profiles.** `darkmatter profile --library` analyzes the trusted files
   themselves (all versions together, keyed by SHA-256) and records, for every member, the
   capabilities and findings it can reach: through its callees, the overrides a virtual call can
   dispatch to, and its type's static constructor. A mod calling a trusted member gets that
   member's profile, Full-access capabilities included, merged over every trusted
   version (the loader decides which copy is loaded). A call into a library with an unprofiled
   version, or to a member no profiled version has, counts as code that was not analyzed. The policy's
   `libraries.exempt` lists the members whose capability is the library's own job and is
   accounted for at the mod (Harmony's patching and reflection helpers), with a reason each.
   A trusted library's attribute on a mod's type or method counts as a call to its constructor.
6. **File access by path origin.** The path operand of each file operation is traced through
   the values it is built from (`Path.Combine`, concatenation, interpolated strings, file-system
   objects) to the APIs and literals it comes from: the mod's folder, the game's folders and
   saves, user folders, environment variables, absolute paths and web addresses. Arguments are
   traced to every analyzed call, fields to every store, results to every value returned. A part
   of a path that cannot be traced (an argument of a method no analyzed code calls, a field other
   code can assign, a virtual method's result, a literal with a `..` segment) counts as outside
   the game. Documents or an environment variable combined with a literal naming the game's
   folder in the same path is the game's folder. Writes into the mod's or
   the game's folders are labelled, because that is where the loader finds code; the policy's
   `fullAccessCombinations` make such a write (or one outside the game) Full access together
   with a network connection. The game's own writes there, reached through the game-API map,
   are not labelled. An XML load (which also takes a web address) whose path begins with a folder
   the check traced is a file read, whatever is appended to it; one whose beginning is not traced
   can be a web address.
7. **Harmony patches by attribute.** `[HarmonyPatch]` and `[HarmonyDelegate]` values are decoded
   from the metadata (every constructor Harmony has: a type, a method name, a type name, a
   `MethodType`; `[HarmonyPatchAll]` means every method of the type), merged with the class's
   and its base classes' attributes as Harmony merges them (it reads them with `inherit: true`).
   A patch class whose base class is in another assembly is reflection the check cannot trace. A target in the
   framework gets that type's capabilities, as reflection on a constant type name does; a game
   target gets the capabilities of the patched member in the game-API map that raise the tier (its
   labels too for a reverse patch or a delegate, which run the target's code); a trusted-library
   target gets its library profile; a target anywhere else is code that was not analyzed.
   Patches on game members otherwise only add "Changes how the game works", and a patch class
   whose patch methods can only observe its target passes nothing of a game or trusted-library
   target on. Transpilers on the game's code are deep game access ("Rewrites the game's code ..."), not
   code generation: `OpCodes` and `Label` values are data, and what an instruction refers to is a
   reflection sink. A transpiler on any other target, or on one the check cannot place, is Full
   access ("Rewrites code other than the game's ...", policy 12).
   The framework and Harmony semantics the check models by name (reflection lookups and sinks,
   collections and LINQ, name filters, path sources and combiners, interpolated strings,
   `ProcessStartInfo`, the folder a method creates, clean expression trees, the parameter types
   that make a patch observing) apply only to members that live in the shared framework, the game
   (for the policy's game path sources) or 0Harmony (policy 12). A type that is only named like one
   (`System.Type` defined in a mod, or in an assembly the check did not analyze) is ordinary code.
8. **Manifest resources.** Every embedded resource is read (never unpacked or loaded) and must
   look like data; see "Couldn't be fully checked" for what counts as an embedded binary. Analyzing an
   embedded assembly as part of the mod is not done yet: it is Full access.
9. **Compiler-generated code.** Collection expressions and `params` spans compile to helpers
   that use `Unsafe`. Those helpers are exempt only when their IL matches the compiler's
   template and each call passes a matching inline-array type and an in-range constant.
10. **Game-API map.** `darkmatter profile` derives, from the game's own assemblies, which labels
   and which capabilities that raise the tier each game method (public or not) leads to, for example
   `GameSaves.MakeSave` changes game saves, and a method that starts whatever its caller names
   starts other programs. A mod calling that method gets them. The policy's `game.exempt` lists
   what the game does on its own account (its native bindings and raw memory use, reading its
   own version), with reasons. The map holds the game's assembly names (the .NET runtime the
   game ships is skipped), method names, capability tags and one example each.
11. **Fail closed.** Undecodable IL, unreadable files, unextractable archives and files whose
   hash changed since extraction are reported and count as Full access. No blind spot leaves a
   mod in No code or Limited access. A game or library profile made by an older tool or with
   a different policy is refused.

The trusted-library allowlist is built from the content index's release ledger
([content-index-releases](https://github.com/KSAModding/content-index-releases)). Each release
archive is verified against its stamped SHA-256, then expanded to per-file DLL hashes across
the full version history of each trust anchor (by default, listings of type `mod-loader`).
[docs/loader-spec.md](docs/loader-spec.md) specifies how a loader can check, at load time, that
it runs only the files that were analyzed.

## Policy

[policy/policy.jsonc](policy/policy.jsonc) holds the capability rules, the label wording, the
tier names and summaries, the Full-access triggers in their three groups (the `fullAccess`
section, and `fullAccessCombinations`, each with its group) and the game-specific path sources.
It is embedded in the tool at build time; `--policy FILE` overrides it. The tool validates it on
load: every capability must be assigned to exactly one of a Full-access group, a label, file-path
tracing or the informational list, and every finding to exactly one Full-access group. Results are stamped with the tool version, the policy version and the
policy file's SHA-256, so a result can be reproduced.

## Requirements

- .NET 10 SDK, for the analyzer and the pipeline
- Python 3.9 or later, for the test harness (standard library only)
- Python 3.11 or later, only for the two reference scripts kept until the pipeline's network
  commands have been run against GitHub (see "Analyze the content index")

## Usage

```sh
dotnet build src/DarkMatter -c Release -o out
dotnet build src/DarkMatter.Pipeline -c Release -o out
```

`darkmatter` is the analyzer. `darkmatter-pipeline` fetches, extracts and builds the inputs for
the content index; it is a separate program so that the analyzer never touches the network or
writes files taken from an archive.

### Analyze one mod

```sh
dotnet out/darkmatter-pipeline.dll build-allowlist --out allowlist.json --library-dir libraries/
dotnet out/darkmatter.dll profile --out game-api-profile.json path/to/game/*.dll
dotnet out/darkmatter.dll profile --library --allowlist allowlist.json --game-profile game-api-profile.json \
    --out library-profiles.json libraries/*/*
dotnet out/darkmatter.dll analyze --allowlist allowlist.json --library-profile library-profiles.json \
    --game-profile game-api-profile.json --name MyMod path/to/mod/*.dll
```

`--library-dir` writes every trusted file to `libraries/<sha256>/`; `profile --library` profiles
them (only files whose hash is on the allowlist). Without `--library-profile`, every call into a
trusted library counts as code that was not analyzed. Profiles record the policy they were made
with: regenerate both profiles whenever the policy or the tool changes.

Add `-v` to show the evidence behind each label and reason, `--json FILE` for machine-readable
results, and `--facts FILE` for the per-file analysis facts. Inputs can also be given as
`@listfile`, one path per line.

### Analyze the content index

```sh
dotnet out/darkmatter-pipeline.dll fetch-releases listings/ downloads/
dotnet out/darkmatter-pipeline.dll extract downloads/ extracted/ --manifest manifest.json
dotnet out/darkmatter-pipeline.dll build-allowlist --out allowlist.json --library-dir libraries/
# game and library profiles as above
dotnet out/darkmatter.dll analyze --allowlist allowlist.json --library-profile library-profiles.json \
    --game-profile game-api-profile.json --manifest manifest.json --json results.json
dotnet out/darkmatter-pipeline.dll compare-results previous-results.json results.json
```

`listings/` is a directory of content-index listing files (`<id>.toml`). `fetch-releases`
downloads every asset of each listing's newest GitHub release (unauthenticated API: 60 calls per
hour; it stops when the limit is reached, and a re-run resumes). `extract` unpacks zip, tar and
tar.gz archives, nested ones up to `--max-depth` levels, and writes the manifest that groups code
files into mods. Archives are untrusted: entries with absolute paths, `..`, links, devices or
names that collide ignoring case are never written, the size limit counts bytes actually
written, and any archive that could not be extracted completely is listed as unextracted, which
the analyzer reports as Full access. `compare-results` prints the counts of the three tiers, of
labels and of Full-access reasons by group, the mods whose tier changed, and the Full-access mods
whose reason groups changed (it also reads results from before policy 13, which had four tiers);
`rank-unclassified FACTS.json --manifest manifest.json` ranks the framework members the policy
does not classify, from `analyze --facts`. Run `dotnet out/darkmatter-pipeline.dll help` for
every option.

`fetch-releases` and `build-allowlist` have not been run against GitHub yet: .NET could not open
TLS connections in the environment they were written in. Everything else in them matches the
Python scripts they replace (`build-allowlist --local-fallback` with a filled archive cache gives
the same allowlist and library files). Until they have been run once and compared,
`scripts/fetch_releases.py` and `scripts/build_allowlist.py` stay as the reference (same
arguments).

### Game-API map

```sh
dotnet out/darkmatter.dll profile --out game-api-profile.json path/to/game/*.dll
dotnet out/darkmatter.dll analyze --game-profile game-api-profile.json --allowlist allowlist.json path/to/mod/*.dll
```

The map is derived from proprietary assemblies, so it is generated locally and never committed.
The tracked policy names game members only (in `game.exempt`), never game code.

## Layout

| Path | Purpose |
|---|---|
| `policy/policy.jsonc` | capability rules, labels, tiers, Full-access triggers and their groups, path sources |
| `src/DarkMatter/Analysis/` | single pass over each assembly: IL decoding, capabilities, reflection, calls, fields, path sources |
| `src/DarkMatter/Evaluation/` | file-path origin tracing, reach propagation, tiers and labels per mod, the game-API map, trusted-library profiles |
| `src/DarkMatter/Cli/` | command line: options, inputs, text and JSON output |
| `src/DarkMatter/Policy.cs` | policy loading, validation and rule matching |
| `src/DarkMatter.Pipeline/Extract/` | `extract`: archive detection, entry name checks, zip and tar extraction into a claimed tree, the manifest |
| `src/DarkMatter.Pipeline/Index/` | `fetch-releases`, `build-allowlist`: HTTPS with retries and rate-limit handling, the listing TOML reader |
| `src/DarkMatter.Pipeline/Results/` | `compare-results`, `rank-unclassified` |
| `scripts/fetch_releases.py`, `scripts/build_allowlist.py` | reference copies of `fetch-releases` and `build-allowlist`, until those have been run against GitHub |
| `scripts/test_fixtures.py` | build the fixtures and check the analyzer and extraction against them |
| `fixtures/` | minimal assemblies for each case |
| `docs/` | threat model, loader verification spec, tier counts of the content index per policy version |

## Testing

```sh
python3 scripts/test_fixtures.py
```

Builds the analyzer and every fixture and checks tiers, labels, evidence, allowlist handling,
the game-API map, fail-closed behaviour, policy validation, archive extraction safety
(`darkmatter-pipeline extract` on hostile archives) and the result tools.

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
waits for the connection to time out.

## Development

`DarkMatter.slnx` contains the analyzer, the pipeline and every fixture; `global.json` pins the
.NET 10 SDK band. Code under `src/` builds with nullable reference types, the recommended .NET
analyzers and code-style enforcement, with warnings treated as errors
(`src/Directory.Build.props`). Fixtures are exempt: they contain code written to be flagged.
Formatting follows `.editorconfig`:

```sh
dotnet format src/DarkMatter/DarkMatter.csproj --verify-no-changes
dotnet format src/DarkMatter.Pipeline/DarkMatter.Pipeline.csproj --verify-no-changes
```

## Known gaps

- **Bounded reflection relies on declared types (policy 10).** `x.GetType()` on a value whose
  declared type is a game or mod type is taken to be that type or one derived from it; IL that
  breaks its own declared types (unverifiable code, which C# does not produce) is not detected.
  A member array from a lookup on a game or mod type that was passed to code the check does not
  follow is bounded to that type, although mod code elsewhere could have put another member into
  it; putting an untraced member into it is caught only where the walker sees the array. Bounded
  reflection grants the capabilities of the members it names on the declared type, not those of
  a derived type's member of the same name.
- **Deep game access is coarse (policy 9).** All direct memory access is deep game access,
  whatever the address: a pointer the mod makes up, or is handed by code the check did not trace,
  is not yet told apart from one the game hands over, although only the latter is bounded to the
  game's memory. Until this is split, the group means "the check cannot follow this", not "this
  stays inside the game". An author who knows the rules can aim for this group alone; see "The
  groups explain the tier" above. (Parts of .NET the policy does not classify and calls into code
  that was not analyzed were in the same tier until policy 13, and are now couldn't be fully
  checked.)
- **Exemptions are reviewed by hand.** The game's native code and direct memory use are exempt
  as a whole (by namespace), because almost every game member reaches them. A game member that
  lets a mod choose the address it reads or writes (a handle passed as `IntPtr`, an unchecked
  native buffer) is not told apart. Harmony's patching and reflection API is exempt from the
  capabilities that implement patching; what is patched is checked at the mod.
- **Overrides in the game contribute capabilities that raise the tier, not labels.** A virtual game
  method's labels come from its own code and callees; what other game types' overrides do counts
  toward the tier only. Calls through a framework interface or base class (`IDisposable`,
  `object.ToString`) on a game or library object are not followed into the object's code.
- **Findings inside the game are not carried.** Reflection the check cannot trace and
  unclassified framework members inside the game's own code do not reach the mods that call it;
  trusted libraries do carry them.
- **A call into a trusted library is merged over every trusted version**, and same-named
  library assemblies share one call model, which can over-report.
- **Dependencies on other mods are not followed.** A call into an assembly that the mod does not
  ship, and that is not trusted, the game or the framework, makes the mod Full access
  (couldn't be fully checked), whatever that other mod's own tier is (Limited access or Full
  access): the other mod's result says what it can do.
- **Framework members are classified by name, by hand.** The policy's `safe` list says which
  framework members need no capability; it is not derived from the framework's own code. A
  framework call that reaches a capability through a member the list wrongly calls safe (for
  example through a virtual call on an object the game hands over) is missed.
- **Results depend on the .NET runtime the tool runs on**, whose shared framework decides which
  assembly names count as the framework. The runtime version is in each result's stamp.
- **The allowlist trusts the ledger as published.** `build-allowlist` verifies archives
  against the ledger's hashes but not the ledger's own attestation. "Trusted" means "the build
  the author published", not "safe".
- **The game-API map covers only the assemblies it was generated from**, and must be
  regenerated for each game update; the game exemptions in the policy were reviewed against one
  game build and must be reviewed again (the profile prints how many members reach a Full-access
  capability, by group). The same holds for library profiles and exemptions when the allowlist changes.
- **Opening a folder (policy 11)** is told apart from starting a program only for a folder the same
  method creates with `Directory.CreateDirectory` just before (in the same block, on the same
  argument or local) and then starts through `Process.Start(string)` or a `ProcessStartInfo` with
  nothing but its file name and `UseShellExecute` set, traced to the mod's or the game's folders and
  ending in a literal name without a dot. Any other folder, and a web address that is not a
  constant, counts as starting a program. A folder replaced by a link between the two calls is
  not detected.
- **Transpilers on the game's code are deep game access as a whole (policy 11).** The check traces what a transpiler's
  instructions name, not the patched method Harmony compiles from them: game instructions moved,
  copied or dropped, and memory or native calls the game method already makes, are not followed.
  An instruction's opcode that is not a constant (taken from another instruction) is accepted as
  one of the game method's own. `OpCodes.Calli` anywhere in a mod counts as native code, even when
  it is only compared. Transpiler helpers that look a member up by name themselves
  (`CodeInstruction.Call`, `LoadField`, `StoreField`, `CallClosure`) carry their library profile,
  which is Full access. Game exemptions that cover a whole namespace (the engine's native and
  memory code) still apply to a method a transpiler rewrites. MonoMod IL manipulation (`ILContext`,
  `ILCursor`) is not modelled: its members carry their library profile, which is Full access.
  Only a transpiler whose target is placed in the game's code stays deep game access (policy 12): the
  mod's own code, a game type known only up to its derived types (which can be the mod's), and a
  `PatchProcessor` given a transpiler (whose original the check does not link to it) count as
  outside, which is system access. A mod that uses the transpiler helpers and also makes a
  `[HarmonyDelegate]` to a member outside the game counts as rewriting it (a reverse patch's
  stand-in can carry a transpiler, and the two are not told apart). Of what the game-API map
  proves on the game's own instructions, only opening a web address or a folder is given back
  (as starting a program) for a game member a code-rewriting mod reaches.
- **Observing patches (policy 11)** are recognized by their signature only: a prefix, postfix or
  finalizer that returns nothing and takes only strings, numbers, `__originalMethod` or `__state`. It
  can still throw (a prefix that throws stops the original), read static game state and change it
  directly, as any mod code can; a struct or enum parameter counts as changing.
- **Name filters (policy 11)** are proved only for a lambda that begins with `m.Name == "constant"`
  (or `string.Equals`) on its parameter and returns false otherwise, and that is created where it is
  used (a lambda that captures a variable). A lambda without captures is cached by the compiler in a
  static field, which the check does not follow: it reaches every member, as before.
- **XmlSerializer is deep game access (policy 11)**, even for a type the check traced: the types it
  fills (from the type's fields, properties and `XmlInclude` attributes) are not enumerated. It is
  deep game access too when the check did not trace the type at all (a generic `typeof(T)`), although
  that type is then not bounded to the game's or the mod's code. This is a deliberate exception to
  the placement principle: the XML cannot choose the types (unlike `BinaryFormatter`), and what
  `XmlSerializer` runs is the parameterless constructors and public setters of types the mod's own
  code names, which is how ordinary mods keep their settings. A
  pre-generated `<Assembly>.XmlSerializers.dll` next to the type's assembly is loaded when present:
  a shipped one is analyzed as one of the mod's files; one the mod writes there is a write into its
  own folder, like any DLL the loader would load. The game's own XML loading is exempt.
- **`foreach` over a user-defined inline array** indexes it with a loop variable, which the check
  cannot bound, so it counts as raw memory access. Collection expressions and `params` spans
  are not affected.
- **Reflection by member name** on a resolved type grants all of that type's capabilities, which
  can over-label. Writing a private framework field through reflection on a resolved type is
  not told apart from other member access on that type.
- **Reflection through parameters, returns and collections is traced coarsely (policy 10).** A
  parameter's or return value's types are the union over every analyzed call or `return`, not
  per call; a helper that takes a `Type` and looks a member up on it reaches the members named
  by every string any call passes, on every type any call passes (all members when a name is not
  traced). A parameter of a public method, or of any method of a type the mod's own reflection
  reaches, is untraced (Full access), even when every caller in the mod passes a traced member.
  Arrays and lists are followed only in the method that made them (or through a field of this
  assembly typed as an array of types or members); a list kept in a field, a dictionary, a tuple,
  an enumerator kept across `yield return`, a LINQ `Select`, or a lambda's parameter is not
  followed. Iterating all of a type's methods (`GetMethods()`) and picking one by name in a lambda
  grants every member's capabilities (labels included). Compiled expression trees are clean only
  for the factories listed above; operators (which find methods on operand types), dynamic
  expressions and by-name factories (`Expression.Field(expr, "name")`) are code generation.
- **Another mod can change this mod's reflection fields through reflection** (for example
  `FieldInfo.SetValue` on this mod's type). Direct assignments from other assemblies are caught
  in their own analysis; reflective ones are not.
- **A type or member handed to other framework APIs** (serializers, `TypeDescriptor`) is not
  followed; only the reflection calls listed above require a traced target.
- **Overloads share a node** in the call model, which can over-label file access.
- **7z, RAR, xz, bzip2, zstd, LZ4 and cabinet archives** are recognized but not extracted, and
  count as Full access; so do zip entries compressed with a method other than stored, deflate or
  deflate64.
- **Embedded resources are recognized, not analyzed.** A program, library or archive embedded as
  a resource is Full access even when it is a harmless managed library (analyzing it in memory
  and checking it against the allowlist is not done yet). A payload with no recognizable bytes
  (compressed with deflate or brotli under a name no bundler uses, encrypted, hidden in other
  data) is not found; reading the assembly's own resources together with a write into the mod's
  or the game's folders, or outside the game, is Full access for that reason.
- **Code-folder writes are a pair of capabilities, not a data flow.** A network connection plus a
  write into the mod's or the game's folders (or a write the check cannot place) is Full access
  whether or not the downloaded bytes are what is written. A Limited-access mod with "Changes
  files in its own or the game's folders" can still write there what it computes or reads from
  the places its other labels name.
- **Harmony patch targets are approximated.** When several attributes on a class or method name a
  type or method, every combination counts. A base class in another of the mod's assemblies is
  treated like one outside the mod (unresolved reflection), not merged. A patched game
  member contributes its capabilities that raise the tier, not its labels (as with overrides in the game
  profile): a prefix that redirects a game method's file write is labelled only as "Changes how
  the game works". The other way round, a patched game member contributes everything its whole
  call tree can reach, although a patch only changes that member's arguments and result (a patch
  class whose patch methods can only observe contributes nothing, see "Observing patches"). A
  `Harmony.Patch` call counts its original like reflection, whatever its patch methods are. A `TargetMethod` whose result is
  traced only grants what the lookup granted (for a trusted-library type, the policy's rules,
  not the library profile).

- **Fields read or written through an unmanaged pointer** (`ldfld`/`stfld` on a native integer
  instead of an object or a managed reference), and the receiver of a value type's instance
  method, are not told apart from ordinary field access and calls: that needs IL type checking
  (an IL verifier). Reads, writes, by-reference arguments, locals and returns are checked.
- **Path tracing is flow-insensitive and approximates string edits.** An argument's origins are
  the union over every analyzed call, a field's over every store; values kept in collections,
  tuples or `string.Format` are untraced (outside the game). `Replace`, `Substring` and similar
  edits are treated as appending to the original path (and as changing where it begins and ends).
  A path that begins with the mod's or the game's folder is taken to be a file path whatever is
  appended (an empty folder path would let the rest begin it). A game or trusted-library member that
  writes a path its caller passes counts as writing outside the game, whatever the caller passes.
- **Reflection on game types is matched by name in the game-API map.** A member inherited from a
  base game type is not found through the derived type; `new T()` with a type argument chosen by
  the caller is not followed into `T`'s constructor; a certificate loaded with
  `X509KeyStorageFlags.PersistKeySet` is not labelled as changing the key store.

## License

MIT. See [LICENSE](LICENSE).
