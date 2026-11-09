# Usage

## Requirements

- .NET 10 SDK, for the analyzer and the pipeline
- Python 3.9 or later, for the test harness (standard library only)
- Python 3.11 or later, only for the two fallback download scripts in `scripts/legacy/` (see
  "The tools underneath")

```sh
dotnet build src/DarkMatter -c Release -o out
dotnet build src/DarkMatter.Pipeline -c Release -o out
```

`darkmatter` is the analyzer. `darkmatter-pipeline` scans the content index or one mod: it
downloads, verifies and extracts release archives and runs the analyzer on them. They are
separate programs, and the pipeline runs the analyzer as its own process, so the process that
reads mod code never touches the network or writes files taken from an archive.

## Scan the content index

```sh
dotnet out/darkmatter-pipeline.dll scan index --game path/to/game
dotnet out/darkmatter-pipeline.dll report darkmatter-state/runs/<run>.json --out report.html
```

`scan index` reads the content index's snapshot
(`https://ksamodding.github.io/content-index-releases/v1/index.json`) and scans the newest
release of every listing: the newest stable one if the listing has one, else its newest of any
status, by semantic version. Yanked releases are skipped. Each release is identified by its
listing id, version and stamped archive SHA-256; its archive is downloaded from the stamped URL
(or a mirror the stamp lists) and verified against that hash before anything else. An archive
that cannot be fetched or does not match its stamp is reported as not scanned, never analyzed in
its place, and the run exits 1. So is a listing whose id cannot name a folder (a Windows device
name, a trailing dot, a separator or `..`, or a name extraction would rename) or that an earlier
listing already has ignoring case (the first is scanned), a release whose
download URL does not end in exactly one file name (a trailing `/`, or an encoded one), and a
listing whose archive cannot be read or extracted because of a file-system error, or that hits
any other error (the reason names the error's type): each fails on its own, nothing is stored for
it, and the other listings are scanned.

Everything is kept in a state folder (`--state DIR`, default `./darkmatter-state`): the
snapshot, verified archives by hash, extracted trees, the allowlist and trusted files, the game
and library profiles, one result per release (`results/<id>/<sha256>.json`) and one document per
run (`runs/`). The allowlist comes from the snapshot's mod loaders, and the profiles are made as
needed, so there is nothing to prepare but the game folder. A release whose stored result has the
current scan key (tool and pipeline versions and the SHA-256 of their assemblies, the .NET
runtime, policy, game DLLs, the allowlist's hashes and names, and the extraction limits) is not
scanned again: a second
run rescans nothing, and a change of policy, tool or pipeline build, game build or a loader
release rescans everything. A release whose download URL now names another file is scanned
again too (result paths start with that name). A result that may come from a passing problem of
the computer (a file-system error while extracting, a file the analyzer could not read) fails
closed as usual but is marked `retry` and scanned again by the next run. A stored result that
cannot be read (damaged, a duplicate key, no result or no tier) is not used: the release is
scanned again, and when it was the listing's last recorded result the change is reported with
nothing to compare (`"previous": "unreadable"`), not as unchanged. Cached profiles are checked
before they are used again (they parse, have the format `darkmatter version` reports and the
current policy's hash, and have every part the analyzer reads, not empty); one that fails is
deleted and made again with a warning, and the library profiles are made again with a new game
profile. A profile just made that fails the same check ends the run with an error. `--full`
rescans everything anyway and makes the profiles again. A `latest.json` that cannot be read is
moved aside (`latest.json.damaged-TIME`) with a warning, and that run reports every listing as new
(and cannot report a listing that has gone since, having no record of it);
`scan mod ID@VERSION` does not read it. When the snapshot cannot be downloaded, or the download is
not a usable snapshot, the copy an earlier run kept is used with a warning that it may be out of
date (a release yanked since then, a trust anchor included, is still treated as it was), and the
run document and stored results mark it (`snapshot.stale`); a download replaces that copy only
once it has been read as a snapshot. These checks catch damage, not edits: the state folder is trusted. Each mod's extracted files are limited to 4 GiB (`--max-extracted-bytes N`;
the stamp records the limits, and another limit is another key); a mod over the limit counts as
not extracted. The extracted trees are kept, so the state folder needs that much disk per large
mod (the largest in the index unpacks to about 2.2 GB). Keep the state folder outside any
version-controlled working tree you run tools in: extraction renames the names tools act on
(below), but a folder inside a repository is still part of it. Each run reports what changed for each listing since its last recorded result:
a new listing, a new release, or a rescan (a new key, `--full` or a retry) that changed the tier,
the labels, the reason groups or the reasons. One scan at a time can use a state folder (it holds
a lock file); a second one exits 1.

Output is text (`--format text`, the default: the counts, the changes, what was not scanned, and
the results of new and changed listings; `--all` for every listing, `-v` for evidence) or the run
document as JSON (`--format json`), which holds every result with every piece of evidence.
`report` renders a run document, or a results file of `darkmatter analyze --json`, as one
self-contained HTML page with no script, to share with people who do not run the tool. Every
string in it is HTML-encoded, with control and format characters (bidirectional overrides,
zero-width characters) shown as `\uXXXX` escapes as in the text output, and its
Content-Security-Policy allows no script and only the page's own style sheet (by hash): names and
evidence come from untrusted archives.

## Scan one mod

```sh
dotnet out/darkmatter-pipeline.dll scan mod StarMap --game path/to/game        # newest release
dotnet out/darkmatter-pipeline.dll scan mod StarMap@0.5.2 --game path/to/game  # a given version
dotnet out/darkmatter-pipeline.dll scan mod path/to/MyMod --game path/to/game  # a local folder, zip or DLLs
```

A listing id is scanned like a listing of the index (a yanked version is refused). Local files,
such as a build before release, are copied or extracted with the same rules as an archive; they
have no stamp, so they are identified by their files' hashes and their result is not stored.

## Results

Each result has the mod's tier, its labels, and its Broad-access reasons in their groups. Labels
and reasons carry a stable id next to their text, and every piece of evidence behind them,
sorted, with the count. File paths are relative to the release's archive, as extracted: a
component renamed by extraction (below) appears renamed, for example `MyMod/_dm_.git/x.dll`. Text output shows the
first 20 lines of evidence per label or reason, the HTML report the first 100; the JSON has all
of them.

## The tools underneath

```sh
dotnet out/darkmatter-pipeline.dll build-allowlist --out allowlist.json --library-dir libraries/
dotnet out/darkmatter.dll profile --out game-api-profile.json path/to/game/*.dll
dotnet out/darkmatter.dll profile --library --allowlist allowlist.json --game-profile game-api-profile.json \
    --out library-profiles.json libraries/*/*
dotnet out/darkmatter.dll analyze --allowlist allowlist.json --library-profile library-profiles.json \
    --game-profile game-api-profile.json --name MyMod path/to/mod/*.dll
```

`scan` runs these itself. `build-allowlist` writes the allowlist alone, and `--library-dir`
writes every trusted file to `libraries/<sha256>/`; `profile --library` profiles them (only files
whose hash is on the allowlist). Without `--library-profile`, every call into a trusted library
counts as code that was not analyzed. Profiles record the policy they were made with, and one
made with another policy is refused. `analyze` takes `-v` for the evidence, `--json FILE` for
machine-readable results, `--facts FILE` for the per-file analysis facts (what the analyzer
observed before the policy was applied, for detection work), `--manifest FILE` for several mods,
and `@listfile` inputs, one path per line. `darkmatter version` prints the stamp results carry, and the profile format
(`profileFormat`) this build writes.

`extract DOWNLOADS EXTRACTED --manifest FILE` unpacks zip, tar and tar.gz archives, nested ones up
to `--max-depth` levels, and writes the manifest that groups code files into mods; `scan` uses the
same extraction. Archives are untrusted: entries with absolute paths, `..`, links, devices or names
that collide ignoring case are never written, the size limit counts bytes actually written
(4 GiB per mod by default; the counted bytes, the file count and the nesting depth are what stop
archive bombs), and any archive that could not be extracted completely is listed as unextracted,
which the analyzer reports as Broad access. A path component named like a version-control, editor
or coding-agent folder or file (`.git`, as a folder or a file, `.gitmodules`, `.gitattributes`,
`.hg`, `.svn`, `.bzr`, `.jj`, `.vscode`, `.idea`, `.cursor`, `.cursorrules`, `.claude`, `CLAUDE.md`,
`CLAUDE.local.md`, `AGENTS.md`, `AGENTS.override.md`, `.gemini`, `GEMINI.md`, `.mcp.json`;
ignoring case (a dotless i counts as i, as on NTFS), Unicode normalization and zero-width
characters) is written with the prefix `_dm_` (`.git/config` becomes `_dm_.git/config`), with a
warning once per name and mod: git, editors and coding agents run in or reading an extracted tree
would otherwise take these as their repository, hooks, tasks or instructions. Every other rule
applies to the renamed name, and one that then collides with another entry (an archive with both
`.git/x` and `_dm_.git/x`) makes the archive unextracted. The analyzer never looks at folder names,
so the rename changes only the paths a report shows. `compare-results` prints the counts of the
three tiers, of labels and of Broad-access reasons by group, the mods whose tier changed, and the
Broad-access mods whose reason groups changed (it also reads results from before policy 13, which
had four tiers, and from before policy 36, which called Broad access "Full access", tier id
`full-access`; `scan` reads stored results from before policy 36 the same way, so the rename alone
is never reported as a change);
`rank-unclassified FACTS.json --manifest manifest.json` ranks the framework members the policy
does not classify, from `analyze --facts`. Run `dotnet out/darkmatter-pipeline.dll help` for
every option.

`scan`'s downloads (the snapshot and the archives, over HTTPS with .NET) have not yet run against
the live index: .NET could not open TLS connections in the environment the code was written in. A full
index scan has run with the archives fetched by another client and put in the state folder's
`archives/`, where `scan` verifies each one against its stamp before use. Until `scan` has
downloaded on its own once, `scripts/legacy/fetch_releases.py` and `scripts/legacy/build_allowlist.py`
(the old GitHub-API path, feeding `extract` and `analyze --manifest`) stay as a fallback.

## Game-API map

```sh
dotnet out/darkmatter.dll profile --out game-api-profile.json path/to/game/*.dll
dotnet out/darkmatter.dll analyze --game-profile game-api-profile.json --allowlist allowlist.json path/to/mod/*.dll
```

The map is derived from proprietary assemblies, so it is generated locally and never committed.
The tracked policy names game members only (in `game.exempt`), never game code. Besides methods and
capability tags it holds the game's assembly, type and member names, each type's base type,
(format 6, policy 34) the game's `[InlineArray]` types with their length and element type, so a
mod's compiler-generated helper over one of them can be checked against the game's own layout, and
(format 7, policy 35) the declared type of each member and the interfaces of each type (type names
only), so a value a mod reads by reflection from a game member can be typed.
