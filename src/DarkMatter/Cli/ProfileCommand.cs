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
        // A file without .NET metadata is no assembly a managed reference loads. A file that could not
        // be read may be one: it is listed, and its assembly is not in "assemblies", so calls into it
        // count as not analyzed (the pipeline does not keep such a profile).
        var skipped = facts.Where(f => f.Classification == FileClass.Error)
            .Select(f => new { file = Path.GetFileName(f.Path), error = f.Error ?? "not analyzed" }).ToList();

        var profile = GameApiProfile.Build(game, policy);
        JsonOutput.Write(output, new {
            note = "Game-API capability map: the game's assembly, type and member names, and its methods with the label and Broad-access capabilities they reach, with one example each. Names and capability tags only; contains no game code. Derived from the game's assemblies: never commit it.",
            format = Inputs.ProfileFormat,
            stamp = JsonOutput.Stamp(policy),
            assemblies = game.Select(f => f.Name).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToList(),
            types = game.SelectMany(f => f.Types.Keys).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList(),
            // Every method and field the game defines, by type, and each game type's base type (other
            // than System.Object): a reference into a game assembly to a member that neither its type nor
            // a base type defines is code this build does not have, not one that reaches nothing.
            members = game.SelectMany(f => f.Types.Keys.Select(t => (t, (string?)null)).Concat(f.Methods.Select(m => m.Name).Concat(f.Fields)
                    .Select(m => m.Split("::", 2)).Where(p => p.Length == 2).Select(p => (p[0], (string?)p[1]))))
                .GroupBy(p => p.Item1, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Select(p => p.Item2).OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList()),
            bases = game.SelectMany(f => f.BaseTypes).Where(kv => kv.Value != "System.Object")
                .DistinctBy(kv => kv.Key, StringComparer.Ordinal).OrderBy(kv => kv.Key, StringComparer.Ordinal).ToDictionary(kv => kv.Key, kv => kv.Value),
            // The game's [InlineArray] types, with their length and element type: a mod's compiler-generated
            // helper over one of them is checked against this (format 6).
            inlineArrays = game.SelectMany(f => f.InlineArrays).DistinctBy(kv => kv.Key, StringComparer.Ordinal).OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .ToDictionary(kv => kv.Key, kv => new { length = kv.Value.Length, element = kv.Value.Element }),
            // The declared type of every member of every game type, "Namespace.Type|Assembly" or "?" (format 7, D2):
            // a mod's lookup by name on a game type types the value it reads. Names and type names only.
            memberTypes = MergedMemberTypes(game),
            // The interfaces each game type implements (format 7, D3): with "bases", the game types a value of a
            // game type known only up to its derived types can be.
            interfaces = game.SelectMany(f => f.Types.Select(kv => (kv.Key, Interfaces: f.BaseTypes.ContainsKey(kv.Key) ? kv.Value.Skip(1).ToList() : kv.Value)))
                .Where(x => x.Interfaces.Count > 0).DistinctBy(x => x.Key, StringComparer.Ordinal).OrderBy(x => x.Key, StringComparer.Ordinal)
                .ToDictionary(x => x.Key, x => x.Interfaces.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList()),
            skipped,
            methods = profile.ToDictionary(kv => kv.Key, kv => kv.Value.Keys.ToList()),
            evidence = profile,
        });
        int broad = profile.Count(kv => kv.Value.Keys.Any(policy.BroadAccess.ContainsKey));
        var byGroup = string.Join(", ", policy.Groups.Select(g => $"{profile.Count(kv => kv.Value.Keys.Any(g.Reasons.ContainsKey))} {g.Name.ToLowerInvariant()}"));
        var unread = game.SelectMany(f => f.Methods.Where(m => m.DecodeFailed).Select(m => m.Name)).Distinct(StringComparer.Ordinal).ToList();
        Console.Error.WriteLine($"profile: {game.Count} game assemblies ({runtime.Count} runtime assemblies skipped), {profile.Count} methods "
            + $"({broad} reach a Broad-access capability: {byGroup}) -> {output}");
        if (unread.Count > 0)
            Console.Error.WriteLine($"warning: {unread.Count} game method{(unread.Count == 1 ? "" : "s")} could not be read ({string.Join(", ", unread.Take(3))}{(unread.Count > 3 ? ", ..." : "")}); calls that reach them count as not analyzed");
        if (skipped.Count > 0) Console.Error.WriteLine($"warning: {skipped.Count} game file{(skipped.Count == 1 ? "" : "s")} could not be read; calls into {(skipped.Count == 1 ? "it" : "them")} count as not analyzed");
        return 0;
    }

    // The game's member types by type, merged over its assemblies as AssemblyFacts records them (a type defined twice
    // with a member of the same kind and name of another type makes that member unknown), in name order.
    static SortedDictionary<string, SortedDictionary<string, string>> MergedMemberTypes(IEnumerable<AssemblyFacts> game) {
        var merged = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        foreach (var f in game)
            foreach (var (type, members) in f.MemberTypes) {
                if (!merged.ContainsKey(type)) merged[type] = new(StringComparer.Ordinal);
                foreach (var (key, value) in members) MemberTypes.Add(merged, type, key, value);
            }
        return new(merged.ToDictionary(kv => kv.Key, kv => new SortedDictionary<string, string>(kv.Value, StringComparer.Ordinal), StringComparer.Ordinal), StringComparer.Ordinal);
    }

    static int Library(Options o, string output, Policy policy) {
        var allowPath = o.Get("--allowlist") ?? throw new UsageException("profile --library needs --allowlist FILE: only trusted files are profiled");
        var allow = Inputs.LoadAllowlist(allowPath);
        // Calls from a library into the game get the game's capabilities, as a mod's calls do.
        var game = o.Get("--game-profile") is { } gp ? Inputs.LoadGameProfile(gp, policy) : null;
        if (game == null) Console.Error.WriteLine("warning: no --game-profile; library calls into the game reach no capabilities");
        var framework = Boundary.SharedFramework();
        var gameAssemblies = game?.Assemblies?.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var analyzer = new Analyzer(policy, Allowlist.Empty, game?.Methods ?? new Dictionary<string, string[]>(), framework, gameAssemblies, game?.InlineArrays, game?.GameTypes);

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
            framework,
            game?.Members,
            game?.Bases,
            game?.Interfaces);
        var profiles = LibraryProfile.Build(files, policy, boundary, game?.Methods ?? new Dictionary<string, string[]>(), game?.Types);
        JsonOutput.Write(output, new {
            note = "Trusted-library profiles, keyed by file SHA-256: every member of each file with the capabilities and findings it reaches (Broad-access ones included), with one example each. Derived from the libraries' assemblies.",
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
