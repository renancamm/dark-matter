// SPDX-License-Identifier: MIT
using System.Text.Json;
using DarkMatter.Cli;

namespace DarkMatter;

/// <summary>darkmatter: static access analysis for Kitten Space Agency mods.</summary>
internal static class Program {
    const string Usage = """
        usage:
          darkmatter analyze [options] [FILE | @LISTFILE]...
              Analyze mod files and report each mod's tier and labels.
              --allowlist FILE     trusted-library allowlist (SHA-256); without it nothing is trusted
              --manifest FILE      manifest.json from `darkmatter-pipeline extract` (one entry per mod);
                                   without it, all FILEs form one mod
              --name NAME          mod name when FILEs are given directly (default: mod)
              --game-profile FILE  game-API capability map from `darkmatter profile`
              --library-profile FILE  trusted-library profiles from `darkmatter profile --library`;
                                   without it, calls into trusted libraries count as not analyzed
              --policy FILE        policy file (default: the built-in policy/policy.jsonc)
              --json FILE          also write the results as JSON
              --facts FILE         also write the per-file analysis facts as JSON
              -v, --verbose        show the evidence behind each label and reason

          darkmatter profile --out FILE [--policy FILE] FILE...
              Write a game-API capability map for the methods of the given game assemblies.

          darkmatter profile --library --allowlist FILE [--game-profile FILE] --out FILE [--policy FILE] FILE...
              Write the profiles of the given trusted library files (only files whose SHA-256 is on
              the allowlist), keyed by hash. Give every trusted version together.

          darkmatter policy
              Print the built-in policy.
        """;

    static int Main(string[] args) {
        try {
            return args.Length == 0 ? Fail(Usage) : args[0] switch {
                "analyze" => AnalyzeCommand.Run(args[1..]),
                "profile" => ProfileCommand.Run(args[1..]),
                "policy" => Print(Policy.EmbeddedText()),
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
