// SPDX-License-Identifier: MIT
using System.Text.Json;
using DarkMatter.Pipeline.Extract;
using DarkMatter.Pipeline.Index;
using DarkMatter.Pipeline.Results;

namespace DarkMatter.Pipeline;

/// <summary>
/// darkmatter-pipeline: fetches the content index's releases, extracts them and builds the
/// trusted-library allowlist, the inputs of <c>darkmatter analyze</c>. Downloads and archives are
/// untrusted: nothing here runs or loads them.
/// </summary>
internal static class Program {
    const string Usage = """
        usage:
          darkmatter-pipeline fetch-releases [--list] LISTINGS DOWNLOADS
              Download every asset of the newest non-draft GitHub release of each listing
              (LISTINGS/<id>.toml, [releases] github and tag_prefix) into DOWNLOADS/<id>/. A mod
              whose folder is not empty is skipped, so a stopped run can be resumed.
              --list               only print each listing's id, repository and tag prefix
              --max-bytes N        size limit per asset (default 4 GiB)

          darkmatter-pipeline extract DOWNLOADS EXTRACTED --manifest FILE [options]
              Extract each DOWNLOADS/<mod>/ into EXTRACTED/<mod>/ and write the manifest for
              `darkmatter analyze --manifest`. Unsafe entries are skipped, and an archive that
              cannot be extracted completely is listed as unextracted (Full access).
              --max-depth N        levels of archives inside archives to extract (default 3)
              --max-bytes N        extracted size limit per mod (default 2 GiB)
              --max-files N        extracted file count limit per mod (default 100000)

          darkmatter-pipeline build-allowlist --out FILE [options]
              Build the trusted-library allowlist from the content index's release ledger: every
              version of each trust anchor, each archive verified against its stamped SHA-256.
              --releases-repo R    ledger repository (default KSAModding/content-index-releases)
              --anchor-types T,..  listing types to trust (default mod-loader)
              --anchor-ids ID,..   extra ids to trust regardless of type
              --only ID,..         limit to these ids
              --cache-dir DIR      verified archives by hash (default $TMPDIR/ksa-archive-cache)
              --local-fallback DIR a ledger checkout, used if the live tree cannot be read
              --library-dir DIR    also write each trusted file to DIR/<sha256>/<file name>, the
                                   input of `darkmatter profile --library`
              --max-bytes N        size limit per archive and per file in it (default 1 GiB)

          darkmatter-pipeline compare-results BEFORE.json [AFTER.json]
              Tier, label and reason counts (Full access and Unverified) of a `darkmatter analyze
              --json` file, or of two, and the mods whose tier changed.

          darkmatter-pipeline rank-unclassified FACTS.json [--manifest FILE] [--top N] [--by member|type|namespace]
              Rank the framework members the policy does not classify by how many mods use them
              (files without --manifest), from `darkmatter analyze --facts`.

        Downloads use GitHub's unauthenticated API (60 calls per hour).
        """;

    static async Task<int> Main(string[] args) {
        try {
            return args.Length == 0 ? Fail(Usage) : args[0] switch {
                "fetch-releases" => await FetchReleasesCommand.Run(args[1..]),
                "extract" => ExtractCommand.Run(args[1..]),
                "build-allowlist" => await BuildAllowlistCommand.Run(args[1..]),
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
