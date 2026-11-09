// SPDX-License-Identifier: MIT
using System.Text.Json;
using DarkMatter.Pipeline.Extract;
using DarkMatter.Pipeline.Index;
using DarkMatter.Pipeline.Report;
using DarkMatter.Pipeline.Results;
using DarkMatter.Pipeline.Scan;

namespace DarkMatter.Pipeline;

/// <summary>
/// darkmatter-pipeline: scans the content index (or one mod) from the index's snapshot, and the
/// tools around it. It downloads, verifies and extracts release archives and runs the analyzer
/// (<c>darkmatter</c>) on them as a separate process. Downloads and archives are untrusted: nothing
/// here runs or loads them.
/// </summary>
internal static class Program {
    const string Usage = """
        usage:
          darkmatter-pipeline scan index --game DIR [options]
              Scan the newest release of every listing in the content index (the newest stable
              one if there is one; yanked releases are skipped). Each archive is verified against
              its stamped SHA-256 first. A release whose result under the current stamp (tool,
              policy, game, allowlist) is already stored is not scanned again.
          darkmatter-pipeline scan mod ID[@VERSION] --game DIR [options]
              Scan one listing's newest release, or the given version.
          darkmatter-pipeline scan mod PATH... --game DIR [options]
              Scan local files: a folder, a zip, or DLLs (an unreleased build). Not stored.
              --game DIR           the game folder; its DLLs make the game profile (required)
              --state DIR          where downloads, profiles and results are kept
                                   (default ./darkmatter-state)
              --snapshot FILE|URL  the index snapshot (default the published one; a downloaded
                                   copy is kept in the state folder and used, with a warning
                                   that it may be out of date, if a download fails or is not a
                                   usable snapshot)
              --full               rescan every release, even those with a stored result, and
                                   make the game and library profiles again
              --format text|json   text (default), or the run document as JSON
              --out FILE           write the output to FILE instead of standard output
              --all                text: show every listing's result, not only new and changed ones
              -v, --verbose        text: show the evidence behind each label and reason
              --name NAME          scan mod PATH: the mod's name (default: the folder or file name)
              --analyzer FILE      darkmatter.dll to run (default: the one next to this program)
              --max-bytes N        size limit per archive (default 4 GiB)
              --max-extracted-bytes N
                                   extracted size limit per mod (default 4 GiB); part of the
                                   scan key, so changing it scans every release again
              --retries N          retries per download (default 3)
              Exits 0 when every listing was scanned or skipped, 1 when one could not be (its
              archive could not be fetched or does not match its stamp, the analyzer failed, or
              any other error with that listing; nothing is stored for it).
              Every run is also saved as a JSON document in the state folder's runs/.

          darkmatter-pipeline report RUN.json --out FILE.html [--title TEXT]
              An HTML report of a scan (a run document, or a results file of `darkmatter analyze
              --json`): one self-contained page with no script, to share with people who do not
              run the tool.

          darkmatter-pipeline build-allowlist --out FILE [options]
              The trusted-library allowlist alone: every release of each trust anchor in the index
              snapshot that is not yanked, each archive verified against its stamped SHA-256.
              --snapshot FILE|URL  the index snapshot (default the published one)
              --anchor-types T,..  listing types to trust (default mod-loader)
              --anchor-ids ID,..   extra ids to trust regardless of type
              --only ID,..         limit to these ids
              --cache-dir DIR      verified archives by hash (default $TMPDIR/ksa-archive-cache)
              --library-dir DIR    also write each trusted file to DIR/<sha256>/<file name>, the
                                   input of `darkmatter profile --library`
              --max-bytes N        size limit per archive and per file in it (default 1 GiB)

          darkmatter-pipeline extract DOWNLOADS EXTRACTED --manifest FILE [options]
              Extract each DOWNLOADS/<mod>/ into EXTRACTED/<mod>/ and write the manifest for
              `darkmatter analyze --manifest`. Unsafe entries are skipped, and an archive that
              cannot be extracted completely is listed as unextracted (Broad access). Entries
              named .git, .gitmodules, .gitattributes, .hg, .svn, .bzr, .jj, .vscode, .idea,
              .cursor, .cursorrules, .claude, CLAUDE.md, CLAUDE.local.md, AGENTS.md,
              AGENTS.override.md, .gemini, GEMINI.md or .mcp.json (any case) are written as
              _dm_NAME.
              --max-depth N        levels of archives inside archives to extract (default 3)
              --max-bytes N        extracted size limit per mod (default 4 GiB)
              --max-files N        extracted file count limit per mod (default 100000)

          darkmatter-pipeline compare-results BEFORE.json [AFTER.json]
              Tier, label and Broad-access reason counts (by group) of a `darkmatter analyze
              --json` file, or of two, and the mods whose tier or reason groups changed.

          darkmatter-pipeline rank-unclassified FACTS.json [--manifest FILE] [--top N] [--by member|type|namespace]
              Rank the framework members the policy does not classify by how many mods use them
              (files without --manifest), from `darkmatter analyze --facts`.

        Downloads use the content index's snapshot and the release URLs it stamps (no GitHub API).
        """;

    static async Task<int> Main(string[] args) {
        try {
            return args.Length == 0 ? Fail(Usage) : args[0] switch {
                "scan" => await ScanCommand.Run(args[1..]),
                "report" => ReportCommand.Run(args[1..]),
                "build-allowlist" => await BuildAllowlistCommand.Run(args[1..]),
                "extract" => ExtractCommand.Run(args[1..]),
                "compare-results" => CompareResultsCommand.Run(args[1..]),
                "rank-unclassified" => RankUnclassifiedCommand.Run(args[1..]),
                "-h" or "--help" or "help" => Print(Usage),
                _ => Fail(Usage),
            };
        } catch (UsageException e) {
            return Fail("error: " + e.Message);
        } catch (InvalidDataException e) {
            return Fail("error: " + e.Message);
        } catch (JsonException e) {
            return Fail("error: malformed JSON: " + e.Message);
        } catch (KeyNotFoundException e) {
            return Fail("error: input file is missing a required field: " + e.Message);
        } catch (IOException e) {
            return Fail("error: " + e.Message);
        } catch (UnauthorizedAccessException e) {
            Console.Error.WriteLine("error: access denied: " + e.Message);
            return 1;
        } catch (ArgumentException e) {
            // A malformed input the checks did not anticipate (a duplicate JSON key, a path with characters the system refuses).
            Console.Error.WriteLine("error: " + e.Message);
            return 1;
        } catch (Exception e) when (e is FetchException or RateLimitException or AnalyzerException or StateBusyException) {
            Console.Error.WriteLine("error: " + e.Message);
            return 1;
        }
    }

    static int Print(string s) {
        Console.WriteLine(s);
        return 0;
    }

    static int Fail(string s) {
        Console.Error.WriteLine(s);
        return 2;
    }
}
