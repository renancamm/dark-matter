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
              --other-game-profile [NAME=]FILE  the map of another build of the game (repeatable):
                                   a game member the --game-profile build lacks is looked up there
              --library-profile FILE  trusted-library profiles from `darkmatter profile --library`;
                                   without it, calls into trusted libraries count as not analyzed
              --policy FILE        policy file (default: the built-in policy/policy.jsonc)
              --json FILE          also write the results as JSON
              --facts FILE         also write the per-file analysis facts as JSON
              -v, --verbose        show the evidence behind each label and reason (the first 20;
                                   --json has all of it)

          darkmatter profile --out FILE [--policy FILE] FILE...
              Write a game-API capability map for the methods of the given game assemblies.

          darkmatter profile --library --allowlist FILE [--game-profile FILE] --out FILE [--policy FILE] FILE...
              Write the profiles of the given trusted library files (only files whose SHA-256 is on
              the allowlist), keyed by hash. Give every trusted version together.

          darkmatter policy
              Print the built-in policy.

          darkmatter version [--policy FILE]
              Print the tool, runtime and policy versions results are stamped with, and the
              profile format `profile` writes (profileFormat), as JSON.
        """;

    static int Main(string[] args) {
        try {
            return args.Length == 0 ? Fail(Usage) : args[0] switch {
                "analyze" => AnalyzeCommand.Run(args[1..]),
                "profile" => ProfileCommand.Run(args[1..]),
                "policy" => Print(Policy.EmbeddedText()),
                "version" => VersionCommand(args[1..]),
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

    static int VersionCommand(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, ["--policy"], []);
        if (o.Positional.Count > 0) throw new UsageException($"unexpected argument {o.Positional[0]}");
        var policy = Policy.Load(o.Get("--policy") is { } pp ? Inputs.Require(pp) : null);
        // The stamp, and the profile format this build writes and reads: darkmatter-pipeline checks
        // the profiles it keeps against it rather than keep its own copy of the number.
        var output = JsonSerializer.SerializeToNode(JsonOutput.Stamp(policy), JsonOutput.Options)!.AsObject();
        output["profileFormat"] = Inputs.ProfileFormat;
        return Print(output.ToJsonString(JsonOutput.Options));
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
