// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;
using DarkMatter.Evaluation;

namespace DarkMatter.Cli;

/// <summary>
/// <c>darkmatter profile</c>: write a game-API capability map for the given game assemblies, or
/// with <c>--library</c>, the profiles of the given trusted library files.
/// </summary>
internal static class ProfileCommand {
    static readonly string[] Valued = ["--out", "--policy", "--allowlist", "--game-profile"];
    static readonly string[] Flags = ["--library"];

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, Flags);
        var output = o.Get("--out") ?? throw new UsageException("profile needs --out FILE");
        var policy = Policy.Load(o.Get("--policy") is { } pp ? Inputs.Require(pp) : null);
        return o.Has(Flags) ? Library(o, output, policy) : Game(o, output, policy);
    }

    static int Game(Options o, string output, Policy policy) {
        if (o.Get("--allowlist") != null || o.Get("--game-profile") != null) throw new UsageException("--allowlist and --game-profile are for profile --library");
        // The game ships its own copy of the .NET runtime; those assemblies are the framework, not the game.
        var framework = Boundary.SharedFramework();
        var analyzer = new Analyzer(policy, Allowlist.Empty, new Dictionary<string, string[]>(), framework, null);
        var inputs = Il.ExpandArgs(o.Positional);
        var runtime = inputs.Where(p => framework.Contains(Path.GetFileNameWithoutExtension(p))).ToHashSet(StringComparer.Ordinal);
        var facts = inputs.Where(p => !runtime.Contains(p)).Select(analyzer.Analyze).ToList();
        foreach (var f in facts.Where(f => !f.IsAnalyzed))
            Console.Error.WriteLine($"warning: {f.Path}: {f.Error ?? f.Classification.ToString()}, skipped");
        var game = facts.Where(f => f.IsAnalyzed).ToList();

        var profile = GameApiProfile.Build(game, policy);
        JsonOutput.Write(output, new {
            note = "Game-API capability map: the game's assembly and type names, and its methods with the label and Full-access capabilities they reach, with one example each. Names and capability tags only; contains no game code. Derived from the game's assemblies: never commit it.",
            format = Inputs.ProfileFormat,
            stamp = JsonOutput.Stamp(policy),
            assemblies = game.Select(f => f.Name).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToList(),
            types = game.SelectMany(f => f.Types.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList(),
            methods = profile.ToDictionary(kv => kv.Key, kv => kv.Value.Keys.ToList()),
            evidence = profile,
        });
        int full = profile.Count(kv => kv.Value.Keys.Any(policy.FullAccess.ContainsKey));
        var byGroup = string.Join(", ", policy.Groups.Select(g => $"{profile.Count(kv => kv.Value.Keys.Any(g.Reasons.ContainsKey))} {g.Name.ToLowerInvariant()}"));
        Console.Error.WriteLine($"profile: {game.Count} game assemblies ({runtime.Count} runtime assemblies skipped), {profile.Count} methods "
            + $"({full} reach a Full-access capability: {byGroup}) -> {output}");
        return 0;
    }

    static int Library(Options o, string output, Policy policy) {
        var allowPath = o.Get("--allowlist") ?? throw new UsageException("profile --library needs --allowlist FILE: only trusted files are profiled");
        var allow = Inputs.LoadAllowlist(allowPath);
        // Calls from a library into the game get the game's capabilities, as a mod's calls do.
        var game = o.Get("--game-profile") is { } gp ? Inputs.LoadGameProfile(gp, policy) : null;
        if (game == null) Console.Error.WriteLine("warning: no --game-profile; library calls into the game reach no capabilities");
        var framework = Boundary.SharedFramework();
        var gameAssemblies = game?.Assemblies?.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var analyzer = new Analyzer(policy, Allowlist.Empty, game?.Methods ?? new Dictionary<string, string[]>(), framework, gameAssemblies);

        // A file is profiled only when its hash is on the allowlist, and each hash once.
        var files = new List<(AssemblyFacts, string)>();
        var native = new SortedDictionary<string, string>(StringComparer.Ordinal);  // sha256 -> allowlist name
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in Il.ExpandArgs(o.Positional)) {
            var f = analyzer.Analyze(path);
            if (f.Sha256 == null || !allow.Hashes.Contains(f.Sha256)) { Console.Error.WriteLine($"warning: {path}: not on the allowlist, skipped"); continue; }
            if (!seen.Add(f.Sha256)) continue;  // the same file again
            var name = allow.ByName.FirstOrDefault(kv => kv.Value.Contains(f.Sha256)).Key ?? Path.GetFileNameWithoutExtension(path);
            if (f.Classification == FileClass.Native) {
                // A file without .NET metadata (an app host, a native library) cannot be what a
                // managed reference to its name loads; analyze leaves it out of that name's versions.
                native[f.Sha256] = name;
                continue;
            }
            if (!f.IsAnalyzed) {
                // No profile: a call into it fails closed in analyze.
                Console.Error.WriteLine($"warning: {path}: {f.Error ?? f.Classification.ToString()}, no profile");
                continue;
            }
            if (!string.Equals(name, f.Name, StringComparison.OrdinalIgnoreCase))
                Console.Error.WriteLine($"warning: {path}: assembly name {f.Name} differs from its allowlist name {name}");
            files.Add((f, name));
        }
        var boundary = new Boundary(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            gameAssemblies,
            policy.GameAssemblies,
            framework);
        var profiles = LibraryProfile.Build(files, policy, boundary, game?.Methods ?? new Dictionary<string, string[]>(), game?.Types);
        JsonOutput.Write(output, new {
            note = "Trusted-library profiles, keyed by file SHA-256: every member of each file with the capabilities and findings it reaches (Full-access ones included), with one example each. Derived from the libraries' assemblies.",
            format = Inputs.ProfileFormat,
            stamp = JsonOutput.Stamp(policy),
            libraries = profiles.OrderBy(p => p.Profile.Name, StringComparer.Ordinal).ThenBy(p => p.Sha256, StringComparer.Ordinal)
                .ToDictionary(p => p.Sha256, p => new {
                    name = p.Profile.Name,
                    assembly = p.Profile.Assembly,
                    types = p.Profile.Types,
                    forwarded = p.Profile.Forwarded.Order(StringComparer.Ordinal).ToList(),
                    members = p.Profile.Members,
                }),
            native,
        });
        int missing = allow.Hashes.Count(h => !native.ContainsKey(h) && !profiles.Any(p => p.Sha256 == h));
        Console.Error.WriteLine($"profile: {profiles.Count} trusted library files profiled, {native.Count} native ({missing} allowlisted files have no profile) -> {output}");
        return 0;
    }
}
