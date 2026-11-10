// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;
using DarkMatter.Evaluation;

namespace DarkMatter.Cli;

/// <summary><c>darkmatter analyze</c>: analyze mod files and report each mod's tier and labels.</summary>
internal static class AnalyzeCommand {
    static readonly string[] Valued = ["--allowlist", "--manifest", "--name", "--game-profile", "--other-game-profile", "--library-profile", "--policy", "--json", "--facts"];
    static readonly string[] Flags = ["-v", "--verbose"];

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, Flags);
        var policy = Policy.Load(o.Get("--policy") is { } pp ? Inputs.Require(pp) : null);
        var allow = o.Get("--allowlist") is { } al ? Inputs.LoadAllowlist(al) : null;
        if (allow == null) Console.Error.WriteLine("warning: no --allowlist; no library is trusted and impersonation checks are off");
        var game = o.Get("--game-profile") is { } gp ? Inputs.LoadGameProfile(gp, policy) : null;
        TrustedLibraries libraries;
        if (o.Get("--library-profile") is { } lp) {
            if (allow == null) throw new UsageException("--library-profile needs --allowlist: profiles apply to the trusted versions it lists");
            libraries = Inputs.LoadLibraryProfiles([lp], policy, allow);
        } else {
            if (allow != null && allow.Hashes.Count > 0)
                Console.Error.WriteLine("warning: no --library-profile; calls into trusted libraries count as not analyzed");
            libraries = new TrustedLibraries((allow ?? Allowlist.Empty).ByName, new Dictionary<string, LibraryProfile>());
        }
        var gameApi = game?.Methods ?? new Dictionary<string, string[]>();
        var framework = Boundary.SharedFramework();
        var gameAssemblies = game?.Assemblies?.ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Other builds of the game ("NAME=FILE", or FILE named by its file name): a game member the
        // profile's build lacks is looked up there (see Evaluator.GameReference).
        var others = new List<OtherGame>();
        foreach (var given in o.GetAll("--other-game-profile")) {
            if (game == null) throw new UsageException("--other-game-profile needs --game-profile: it only answers for members that build lacks");
            int eq = given.IndexOf('=');
            var (name, file) = eq > 0 ? (given[..eq], given[(eq + 1)..]) : (Path.GetFileNameWithoutExtension(given), given);
            var other = Inputs.LoadGameProfile(file, policy);
            if (other.Assemblies == null) throw new InvalidDataException($"game profile {file} has no assembly list; it cannot answer for another game build");
            others.Add(new OtherGame(name, new Boundary((allow ?? Allowlist.Empty).Names, other.Assemblies.ToHashSet(StringComparer.OrdinalIgnoreCase),
                policy.GameAssemblies, framework, other.Members, other.Bases, other.Interfaces), other.Methods));
        }
        var analyzer = new Analyzer(policy, allow ?? Allowlist.Empty, gameApi, framework, gameAssemblies, game?.InlineArrays, game?.GameTypes,
            // With --facts the walker also notes what produced each value it does not follow (the "untraced" list).
            explain: o.Get("--facts") != null);
        var boundary = new Boundary(
            (allow ?? Allowlist.Empty).Names,
            gameAssemblies,
            policy.GameAssemblies,
            framework,
            game?.Members,
            game?.Bases,
            game?.Interfaces);

        List<ModListing> listings;
        if (o.Get("--manifest") is { } mp) {
            if (o.Positional.Count > 0) throw new UsageException("give either --manifest or files, not both");
            listings = Inputs.LoadManifest(mp);
        } else {
            var files = Il.ExpandArgs(o.Positional).Select(p => (p, (string?)null)).ToList();
            listings = [new ModListing(o.Get("--name") ?? "mod", files, [], [])];
        }

        // Analyze each distinct file once. Every path is read and hashed (the bytes hashed are the
        // bytes analyzed); a file whose hash differs from the manifest is not analyzed, and one with
        // the same hash as a file already analyzed reuses its facts.
        var byPath = new Dictionary<string, AssemblyFacts>(StringComparer.Ordinal);
        var bySha = new Dictionary<string, AssemblyFacts>(StringComparer.Ordinal);
        AssemblyFacts? FactsFor(string path, string? sha) {
            if (!byPath.TryGetValue(path, out var f)) {
                var bytes = Analyzer.Read(path, out var error);
                var hash = bytes != null ? Il.Sha256(bytes) : null;
                f = hash != null && bySha.TryGetValue(hash, out var known) ? known : analyzer.Analyze(path, bytes, error);
                byPath[path] = f;
                if (f.Sha256 != null) bySha.TryAdd(f.Sha256, f);
            }
            return sha == null || sha == f.Sha256 ? f : null;
        }

        var results = new SortedDictionary<string, ModResult>(StringComparer.Ordinal);
        foreach (var listing in listings) {
            var mod = new ModInput(listing.Name, [.. listing.Files.Select(f => new ModFile(listing.Shown(f.Path), FactsFor(f.Path, f.Sha256)))],
                listing.Unextracted, [.. listing.Scripts.Select(listing.Shown)]);
            results[listing.Name] = Evaluator.Evaluate(mod, policy, boundary, libraries, gameApi, game?.Types, others, game?.GameTypes);
        }

        TextReport.Print(Console.Out, results, o.Has(Flags));
        if (o.Get("--json") is { } jp)
            JsonOutput.Write(jp, new { stamp = JsonOutput.Stamp(policy), mods = results });
        if (o.Get("--facts") is { } fp)
            JsonOutput.Write(fp, new { stamp = JsonOutput.Stamp(policy), files = byPath.Values.Distinct().OrderBy(f => f.Path, StringComparer.Ordinal).Select(f => FactsJson(f, boundary.Framework)) });
        return 0;
    }

    static string Atoms(IEnumerable<string> atoms) => string.Join(", ", atoms.Order(StringComparer.Ordinal));

    static object FactsJson(AssemblyFacts f, IReadOnlySet<string> framework) {
        var caps = f.Caps.Concat(f.Methods.SelectMany(m => m.Caps))
            .GroupBy(e => e.Cap).OrderBy(g => g.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Detail).Distinct().ToList());
        return new {
            f.Path,
            f.Sha256,
            f.Name,
            f.Classification,
            f.Error,
            caps,
            unresolvedReflection = f.Methods.SelectMany(m => m.UnresolvedReflection).ToList(),
            // For each untraced value at a reflection sink or given to a Type or member node: what it is and what produced it.
            untraced = f.Methods.SelectMany(m => m.Untraced).Select(u => $"{u.What}  [{u.Why}]").Distinct().ToList(),
            // Reflection known only up to a type's derived types or an assembly, decided per mod by where that is.
            boundedReflection = f.Methods.SelectMany(m => m.BoundedReflection).Select(b => $"{b.Detail}  ({(b.Type == "*" ? "any type" : b.Type)} in {b.Assembly ?? "?"})").ToList(),
            // Reflection on values read from Type and member fields, resolved per mod from the fields' writers.
            fieldReflection = f.Methods.SelectMany(m => m.FieldReflection).Select(r => r.Detail).ToList(),
            // What each method gives Type and member nodes (fields, arguments, returns): resolved types, other nodes' values, untraced values.
            reflectionStores = f.Methods.SelectMany(m => m.ReflectionStores.SelectMany(kv => kv.Value.Select(h => $"{kv.Key}  <-  {m.Name}  [{(h.Member ? "member of " : "")}{h.Type}{(h.Assembly != null ? " in " + h.Assembly : "")}]"))
                .Concat(m.FieldCopies.SelectMany(kv => kv.Value.Select(g => $"{kv.Key}  <-  {m.Name}  [copy of {g}]")))
                .Concat(m.UntrackedStores.Select(k => $"{k}  <-  {m.Name}  [untraced]"))).Distinct().ToList(),
            // Harmony patches applied by hand whose HarmonyMethod went only to Harmony.Patch (R3): the patch method and what the original was traced to.
            // What Harmony passes a method's object parameters when it is handed over as a patch (R10): "Type::Method#N = how".
            patchParameters = f.Methods.SelectMany(m => m.PatchParameters.OrderBy(kv => kv.Key).Select(kv => $"{m.Name}#{kv.Key} = {PatchParameter.Describe(kv.Value)} of the original")).ToList(),
            manualPatches = f.Methods.SelectMany(m => m.ManualPatches).Select(p => $"{p.Detail}  [original: {(p.Originals != null ? string.Join(", ", p.Originals.Select(h => $"{h.Type}{(h.Value?.Sole is { } sole ? "::" + sole : " (not known to be declared by that type alone)")}")) : p.OriginalNode ?? "untraced")}]").Distinct().ToList(),
            // Types whose fields are written through reflection ("*": unknown, "T+": T or a type derived from it).
            reflectionFieldWrites = f.Methods.SelectMany(m => m.ReflectionFieldWrites.Select(w => $"{w}  <-  {m.Name}")).Distinct().ToList(),
            // Types reached by reflection, resolved per mod by where they live.
            reflectedTypes = f.Methods.SelectMany(m => m.ReflectedTypes).Select(r => r.Assembly == null ? r.Detail : $"{r.Detail}  (in {(r.Assembly.Length > 0 ? r.Assembly : "?")})").Distinct().ToList(),
            // Members Harmony transpilers rewrite, placed per mod (Broad access unless the game's code).
            rewriteTargets = f.Methods.SelectMany(m => m.RewriteTargets).Select(r => $"{r.Detail}  [{(r.Node ?? (r.Type != null ? r.Type + (r.Derived ? "+" : "") + " in " + (r.Assembly ?? "?") : "untraced"))}{(r.IfRewrites ? ", if the mod rewrites code" : "")}]").Distinct().ToList(),
            // File operations and where their paths come from (path atoms, resolved per mod).
            fileOperations = f.Methods.SelectMany(m => m.FileOps.Select(o => $"{o.Member}  <-  {m.Name}  [{Atoms(o.Path)}]")).Distinct().ToList(),
            // What the path atoms above refer to: arguments passed, path fields stored, paths returned.
            pathArguments = f.Methods.SelectMany(m => m.PathArguments.Select(kv => $"{kv.Key}  <-  {m.Name}  [{Atoms(kv.Value)}]")).Distinct().ToList(),
            pathStores = f.Methods.SelectMany(m => m.PathStores.Select(kv => $"{kv.Key}  <-  {m.Name}  [{Atoms(kv.Value)}]")).Distinct().ToList(),
            pathReturns = f.Methods.Where(m => m.PathReturns.Count > 0).Select(m => $"{m.Key}  [{Atoms(m.PathReturns)}]").Distinct().ToList(),
            comActivation = f.Methods.SelectMany(m => m.ComActivation).ToList(),
            decodeFailures = f.Methods.Where(m => m.DecodeFailed).Select(m => m.Name).ToList(),
            pinvokes = f.PInvokes,
            assemblyRefs = f.AssemblyRefs,
            // Framework members the policy does not classify (what the triage loop ranks).
            unclassifiedReferences = f.Methods.SelectMany(m => m.ExternalRefs)
                .Where(r => !r.Classified && framework.Contains(r.Assembly))
                .Select(r => r.Member).Distinct().Order(StringComparer.Ordinal).ToList(),
            // Members of other assemblies outside the framework (game, trusted libraries, other mods): "Assembly: Type::Member".
            externalReferences = f.Methods.SelectMany(m => m.ExternalRefs)
                .Where(r => !framework.Contains(r.Assembly))
                .Select(r => $"{r.Assembly}: {r.Member}").Distinct().Order(StringComparer.Ordinal).ToList(),
        };
    }
}
