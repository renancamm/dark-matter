# Dark Matter

Dark Matter is a static analyzer for Kitten Space Agency (KSA) mods. It reads a mod's compiled .NET
code without running it and lists what the code can reach, such as the internet, files outside the
game or other programs. It then puts the mod in one of three tiers, depending on whether the check
could follow all of the code.

> **Status:** a prototype for a proof of concept.

## Design principles

- **Capabilities, not threats.** A tier says what the code can do, not whether the mod is harmful.
- **Default deny.** Anything the check can't follow, or doesn't expect, is Broad access.
- **Mods are expected to use the game.** Calls into the game and mod loaders count as normal.

## Tiers and labels

Every mod gets one of three tiers:

- **No code**: Only adds content. It can't run programs.
- **Limited access**: It can only do what's listed.
  - **Labels**: the complete list of what the code can do, such as "Connects to the internet" or
    "Changes game saves".
- **Broad access**: It can do anything a program on your computer can.
  - **Labels**: what the check saw, not a complete list.
  - **Groups**: why it is Broad access: Deep game access, System access or Couldn't be fully
    checked.

Each label and group comes with the evidence behind it. All labels, groups and their criteria are
in [docs/tiers-and-labels.md](docs/tiers-and-labels.md).

## How it works

Two programs do the work. `darkmatter-pipeline` downloads and extracts each mod. `darkmatter`, the
analyzer, scans it in a separate process that never uses the network.

### The pipeline

```
  Content index: every mod release, stamped with the SHA-256 of its archive
        |
        v
  [a] Download the release ........ doesn't match its stamp: not scanned
        |
        v
  [b] Extract the archive ......... unsafe entries refused: Broad access
        |
        v
  [c] Scan the mod's files ........ the next diagram
        |
        v
  [d] Store the result ............ compare with the last run: a new
        |                           release, a changed tier, a new label?
        v
  Text, JSON or HTML report
```

### The scan

```
  The mod's files
  MyMod.dll, parts/*.json, textures/*.png, ...
        |
        v
  [1] Sort the files
        |   textures, parts, sounds ................... content: nothing to check
        |   .NET code (.dll) .......................... read in step 2
        |   a mod loader's library .................... trusted only if its SHA-256
        |                                               matches a published release
        |   native program, script, unreadable file ... can't be checked: Broad access
        v
  [2] Read the code without running it
        |   A compiled .dll still holds every instruction, and each instruction
        |   names the exact feature it uses. The scan lists them, method by method:
        |
        |       Update()  uses  HttpClient.GetByteArrayAsync
        |       Update()  uses  File.WriteAllBytes
        v
  [3] For each one, ask: can the check list everything it could lead to?
        |
        |   The answer comes from:
        |       .NET features ........ the policy's rules (policy/policy.jsonc)
        |       the game's methods ... the game map, made from your copy of the game
        |       trusted libraries .... their profiles, made the same way
        |       the mod's own code ... read along with it
        |
        |   yes .... a capability      HttpClient.GetByteArrayAsync: network
        |                              File.WriteAllBytes: file write, and the path is
        |                              traced to the mod's own folder
        |
        |   no ..... Broad access,     Process.Start("x.exe"): what x.exe does is unknown
        |            with the reason   a method called by a name made while the game runs
        |                              a feature the policy doesn't know
        v
  [4] Add it up for the whole mod
        |   each capability ........ a label         network: "Connects to the internet"
        |   risky pairs ............ Broad access    network + writing where the game
        |                                            loads code from
        v
  [5] The result
        Tier ......... Broad access
         > Labels .... Connects to the internet
                       Changes files in its own or the game's folders
         > Reasons ... System access: connects to the internet and
                       changes files where the game loads code from
         > Evidence .. HttpClient.GetByteArrayAsync  <-  Update()
                       File.WriteAllBytes            <-  Update()
```

### The policy

Step 3 uses the policy, [policy/policy.jsonc](policy/policy.jsonc): one file of rules for the .NET
features a mod can use. A rule gives either a capability and the label players see (anything in
`System.Net.Http.` is `network`, shown as "Connects to the internet") or a Broad-access reason. The
policy also lists the capability pairs that are Broad access together, and the features that are
safe. Calls into the game and trusted libraries use the game map and the library profiles instead.
The game map is built locally from your copy of the game and is never published.

- A .NET feature that matches no rule and isn't on the safe list makes the mod Broad access
  (Couldn't be fully checked).
- The tool checks the policy when it starts. Every capability must lead to exactly one outcome, or
  the tool refuses to run.
- Every result records the tool version, the policy version and the policy file's SHA-256.
  [docs/policy-changelog.md](docs/policy-changelog.md) lists what changed at each version.

The details are in [docs/how-it-works.md](docs/how-it-works.md).

## Quick start

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download) and a local copy of the game.

```sh
dotnet build src/DarkMatter -c Release -o out
dotnet build src/DarkMatter.Pipeline -c Release -o out

# Scan the newest release of every mod in the content index
dotnet out/darkmatter-pipeline.dll scan index --game path/to/game

# Render a run as a self-contained HTML page to share
dotnet out/darkmatter-pipeline.dll report darkmatter-state/runs/<run>.json --out report.html

# Scan one mod: a listing id, a given version, or a local folder, zip or DLLs
dotnet out/darkmatter-pipeline.dll scan mod StarMap --game path/to/game
dotnet out/darkmatter-pipeline.dll scan mod StarMap@0.5.2 --game path/to/game
dotnet out/darkmatter-pipeline.dll scan mod path/to/MyMod --game path/to/game
```

Results are kept in a state folder (`darkmatter-state/` by default; keep it outside any git working
tree). A release already scanned with the same tool, policy and game is not scanned again. Each run
reports what changed since the last one: a new listing, a new release, or a changed tier, label or
reason. All commands and options are in [docs/usage.md](docs/usage.md).

## Limits

- Each mod is analyzed against **one game build**. A scan given other builds looks up the game
  members that build lacks in them ([docs/usage.md](docs/usage.md#several-game-builds)).
- **A mod's tier covers its own code.** The mods it requires are noted with their own tier
  ([docs/usage.md](docs/usage.md#dependencies)). **Calls into another mod are not followed**: such a call
  counts as code that was not analyzed.
- **Embedded resources are recognized, not analyzed.** A mod that embeds a program or library is
  Broad access.
- **Labels are independent.** A mod that connects to the internet and reads files outside the game
  gets both labels. The check doesn't show whether one feeds the other.
- `scan`'s own downloads **haven't run against the live content index yet**. Scans so far used
  archives fetched by another client and verified by `scan`.

Every known gap, and how it fails toward Broad access, is in
[docs/known-gaps.md](docs/known-gaps.md).

## Documentation

| Document | What it covers |
|---|---|
| [docs/tiers-and-labels.md](docs/tiers-and-labels.md) | The complete criteria for every tier, group and label |
| [docs/how-it-works.md](docs/how-it-works.md) | How the analyzer decides, step by step, and the policy file |
| [docs/usage.md](docs/usage.md) | Every command: scanning the index or one mod, results, reports, the lower-level tools |
| [docs/known-gaps.md](docs/known-gaps.md) | What the check doesn't see yet, and how each gap fails toward Broad access |
| [docs/policy-changelog.md](docs/policy-changelog.md) | What changed at each policy version |
| [docs/development.md](docs/development.md) | Repository layout, building, testing, and changing a detection rule |
| [docs/style-guide.md](docs/style-guide.md) | How to write the README and the docs |
| [fixtures/README.md](fixtures/README.md) | The test fixtures and what each one checks |

## License

MIT. See [LICENSE](LICENSE).
