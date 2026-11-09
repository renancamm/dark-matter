// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>Applies the policy to a mod's facts and produces its tier and labels.</summary>
internal static class Evaluator {
    const int MaxEvidence = 5;

    /// <param name="mod">The mod's files and what extraction reported.</param>
    /// <param name="policy">The policy to apply.</param>
    /// <param name="boundary">Resolves referenced assemblies (mod, trusted, game, framework).</param>
    /// <param name="libraries">Trusted-library profiles.</param>
    /// <param name="gameApi">The game-API map: game member -> capabilities it reaches (empty without a game profile).</param>
    /// <param name="gameTypes">The game's types, from the game profile; null without one.</param>
    public static ModResult Evaluate(ModInput mod, Policy policy, Boundary boundary, TrustedLibraries libraries, IReadOnlyDictionary<string, string[]> gameApi,
        IReadOnlySet<string>? gameTypes) {
        var files = mod.Files.Select(f => new FileResult(f.Path, f.Facts?.Sha256, f.Facts?.Name, f.Facts?.Classification)).ToList();
        if (mod.Files.Count == 0 && mod.Unextracted.Count == 0 && mod.Scripts.Count == 0)
            return Result(policy, Tier.NoCode, [], [], [], [], files);

        var findings = new Dictionary<string, List<string>>();  // fullAccess key -> evidence
        var caps = new Dictionary<string, List<string>>();      // capability -> evidence
        var warnings = new List<string>();
        var trusted = new SortedSet<string>(StringComparer.Ordinal);

        var analyzed = new List<AssemblyFacts>();
        foreach (var (path, f) in mod.Files) {
            if (f == null) { Add(findings, "not-analyzed", path); continue; }
            switch (f.Classification) {
                case FileClass.Error: Add(findings, "unreadable-file", $"{path}: {f.Error}"); break;
                case FileClass.Native: Add(findings, "native-binary", path); break;
                case FileClass.LibraryKnown: trusted.Add(f.Name); break;
                case FileClass.LibraryImpersonation:
                    warnings.Add($"{f.Name} is named like a trusted library, but its hash is not on the allowlist; analyzed as mod code");
                    analyzed.Add(f);
                    break;
                case FileClass.Mod: analyzed.Add(f); break;
            }
        }
        foreach (var a in mod.Unextracted) Add(findings, "unextracted-archive", a);
        foreach (var s in mod.Scripts) Add(findings, "ships-script", s);

        // A shipped file named like the framework, the game or a trusted library (other than the
        // trusted copy itself) is not what a reference to that name loads; whatever it is meant
        // for, the check cannot tell which of the two runs.
        foreach (var f in analyzed)
            foreach (var name in new[] { Path.GetFileNameWithoutExtension(f.Path), f.Name }.Distinct(StringComparer.OrdinalIgnoreCase))
                if (boundary.Resolve(name, new HashSet<string>()) is var kind and not AssemblyKind.Unanalyzed)
                    Add(findings, "name-collision", $"{f.Path}: named {name}, like {(kind == AssemblyKind.Trusted ? "a trusted library" : kind == AssemblyKind.Game ? "a game assembly" : "a .NET assembly")}");

        // Capabilities reached another way than a direct reference (reflection, patches) have a
        // path the check cannot trace: their file capabilities count as outside the game.
        void Cap(string cap, string detail) {
            if (Policy.Findings.Contains(cap))
                Add(findings, cap, detail);
            else if (policy.FileKinds.TryGetValue(cap, out var kind))
                Add(caps, kind == FileOpKind.Write ? "file-write-outside" : "file-read-outside", detail + "  (path not traceable)");
            else
                Add(caps, cap, detail);
        }

        var methods = analyzed.SelectMany(a => a.Methods).ToList();
        foreach (var e in analyzed.SelectMany(a => a.Caps).Concat(methods.SelectMany(m => m.Caps))) {
            // Silence on purpose: direct file operations are path-traced below.
            if (policy.FileKinds.ContainsKey(e.Cap) && e.Origin == Origin.Reference) continue;
            Cap(e.Cap, e.Detail);
        }
        var own = OwnAssemblies(mod);
        var access = new TypeAccess(policy, boundary, own, analyzed.SelectMany(a => a.Types.Keys).ToHashSet(StringComparer.Ordinal), libraries, gameApi, gameTypes);
        var provenance = new FieldProvenance(analyzed, methods, access);
        foreach (var (_, e) in FileAccess.Classify(analyzed, policy, provenance.FieldsWritten)) Add(caps, e.Cap, e.Detail);
        foreach (var m in methods)
            foreach (var r in m.ReflectedTypes)
                foreach (var (cap, detail) in access.Reach(r.Type, r.Assembly, provenance.Members(r.Members, r.NameNode, r.Lookup), r.PatchTarget ? TypeAccess.PatchUse(r.Patch) : TypeUse.Reflection, frameworkCaps: false, r.Detail))
                    Cap(cap, detail);
        var unresolvedFields = new List<(MethodFacts, string)>();
        var boundedFields = new List<(MethodFacts, string)>();
        var fieldCaps = new List<(MethodFacts, Evidence)>();
        provenance.Resolve(unresolvedFields, boundedFields, fieldCaps);
        foreach (var (_, d) in unresolvedFields) Add(findings, "unresolved-reflection", d);
        foreach (var (_, d) in boundedFields) Add(findings, "bounded-reflection", d);
        foreach (var (_, e) in fieldCaps) Cap(e.Cap, e.Detail);
        foreach (var a in analyzed) {
            foreach (var d in a.EmbeddedBinaries) Add(findings, "embedded-binary", $"{a.Name}: {d}");
            foreach (var d in a.UndecodedPatches) Add(findings, "unresolved-reflection", d);
        }
        foreach (var m in methods) {
            foreach (var d in m.UnresolvedReflection) Add(findings, "unresolved-reflection", d);
            // Known only up to a type's derived types, or an assembly: bounded when that is the
            // game's or the mod's own code (deep game access), unresolved otherwise.
            foreach (var b in m.BoundedReflection)
                if (access.Bounded(b.Type, b.Assembly)) Add(findings, "bounded-reflection", b.Detail);
                else Add(findings, "unresolved-reflection", b.Detail + "  (not the game's or the mod's code)");
            foreach (var d in m.ComActivation) Add(findings, "com-activation", d);
            if (m.DecodeFailed) Add(findings, "decode-failure", m.Name);
        }
        References(analyzed, own, boundary, libraries, findings, caps);
        PatchTargets(analyzed, access, findings, caps, Cap);
        RewriteTargets(analyzed, methods, access, provenance, caps.ContainsKey("code-rewrite"), findings);
        if (caps.ContainsKey("code-rewrite")) {
            // A transpiler's instructions are traced through Harmony's own members: an instruction whose
            // fields are written by reflection can hold any operand.
            if (provenance.FieldsWritten("HarmonyLib.CodeInstruction"))
                Add(findings, "unresolved-reflection", "the fields of Harmony's CodeInstruction (an instruction's operand) are written through reflection, which the check does not follow");
            // A game exemption that names a type or member assumes the game's own code runs there (a check
            // before a start, a constant name): a mod that rewrites game code gets back what it stops on
            // the game members it reaches by reflection or patches.
            foreach (var m in methods)
                foreach (var r in m.ReflectedTypes)
                    foreach (var (cap, detail) in access.RewriteExempted(r.Type, r.Assembly, provenance.Members(r.Members, r.NameNode, r.Lookup), r.Detail))
                        Cap(cap, detail);
            foreach (var t in analyzed.SelectMany(a => a.PatchTargets).Where(t => t.Type != null))
                foreach (var (cap, detail) in access.RewriteExempted(t.Type!, t.Assembly, t.Member != null ? [t.Member] : null, t.Detail))
                    Cap(cap, detail);
        }
        foreach (var (cap, ev) in caps)
            if (policy.RaisesTier(cap)) foreach (var e in ev) Add(findings, cap, e);

        // Labels are reported in every tier: in Limited access they are the complete list, in Full
        // access what the check saw.
        var labels = policy.Labels
            .Select(l => new Finding(l.Text, [.. l.Caps.Where(caps.ContainsKey).SelectMany(c => caps[c]).Distinct().Take(MaxEvidence)]))
            .Where(f => f.Evidence.Count > 0).ToList();
        // Every group with a reason is kept: a mod whose reasons move from one group to another
        // between releases (deep game access only, then system access too) stays visible.
        var groups = new List<GroupResult>();
        foreach (var g in policy.Groups) {
            List<Finding> reasons = [.. g.Reasons
                .Where(kv => findings.ContainsKey(kv.Key))
                .Select(kv => new Finding(kv.Value, [.. findings[kv.Key].Distinct().Take(MaxEvidence)]))];
            // Capabilities that are Limited access one by one, but together let a mod do what Full
            // access covers (download code and put it where the loader picks it up).
            foreach (var c in policy.Combinations.Where(c => c.Group == g.Id && c.Caps.All(caps.ContainsKey)))
                reasons.Add(new Finding(c.Text, [.. c.Caps.Select(cap => $"{cap}: {caps[cap][0]}")]));
            if (reasons.Count > 0) groups.Add(new(g.Id, g.Name, g.Summary, reasons));
        }
        return Result(policy, groups.Count > 0 ? Tier.FullAccess : Tier.LimitedAccess, labels, groups, warnings, [.. trusted], files);
    }

    static ModResult Result(Policy policy, Tier tier, IReadOnlyList<Finding> labels, IReadOnlyList<GroupResult> groups,
        IReadOnlyList<string> warnings, IReadOnlyList<string> trusted, IReadOnlyList<FileResult> files) {
        var text = policy.Tiers[tier.Id()];
        return new(tier, text.Name, text.Summary, labels, groups, warnings, trusted, files);
    }

    // The mod's own assembly names. A shipped copy of a trusted library is not the mod's own code:
    // calls into it resolve to the trusted library and its profile, like calls into the loader's copy
    // (and so does any other name the Boundary resolves before the mod's files).
    static HashSet<string> OwnAssemblies(ModInput mod) {
        var own = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, f) in mod.Files) {
            if (f?.Classification == FileClass.LibraryKnown) continue;
            own.Add(Path.GetFileNameWithoutExtension(path));
            if (f != null) own.Add(f.Name);
        }
        return own;
    }

    // Every reference into another assembly must land in code that was analyzed, a trusted
    // library member whose profile is known, the game, or a framework member the policy classifies.
    static void References(List<AssemblyFacts> analyzed, HashSet<string> own, Boundary boundary, TrustedLibraries libraries,
        Dictionary<string, List<string>> findings, Dictionary<string, List<string>> caps) {
        foreach (var a in analyzed) {
            var called = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in a.Methods)
                foreach (var r in m.ExternalRefs) {
                    switch (boundary.Resolve(r.Assembly, own)) {
                        case AssemblyKind.Unanalyzed:
                            called.Add(r.Assembly);
                            Add(findings, "unanalyzed-call", $"{r.Member} in {(r.Assembly.Length > 0 ? r.Assembly : "an assembly the check cannot determine")}  <-  {m.Name}");
                            break;
                        case AssemblyKind.Framework when !r.Classified:
                            Add(findings, "unclassified-reference", $"{r.Member}  <-  {m.Name}");
                            break;
                        case AssemblyKind.Trusted:
                            if (libraries.Lookup(r.Assembly, r.Member, out var why) is not { } reached) {
                                called.Add(r.Assembly);
                                Add(findings, "unanalyzed-call", $"{r.Member} in trusted library {r.Assembly} ({why})  <-  {m.Name}");
                                break;
                            }
                            // The profile already leaves out what the policy's libraries.exempt stops.
                            foreach (var (cap, example) in reached)
                                Add(Policy.Findings.Contains(cap) ? findings : caps, cap,
                                    $"{r.Member} (trusted library {r.Assembly})  <-  {m.Name}  [reaches: {example}]");
                            break;
                    }
                }
            // A trusted library's attribute constructor runs when the attribute is read (by the
            // runtime, Harmony or the loader): it reaches what its profile says.
            foreach (var (r, owner) in a.AttributeRefs) {
                // Silence on purpose: framework and game attribute constructors only store their
                // arguments (see AssemblyWalker.AttributeRefs), and an assembly that was not
                // analyzed is reported below as a reference to it.
                if (boundary.Resolve(r.Assembly, own) != AssemblyKind.Trusted) continue;
                if (libraries.Lookup(r.Assembly, r.Member, out var why) is not { } reached) {
                    called.Add(r.Assembly);
                    Add(findings, "unanalyzed-call", $"attribute {r.Member} in trusted library {r.Assembly} ({why})  <-  {owner}");
                    continue;
                }
                foreach (var (cap, example) in reached)
                    Add(Policy.Findings.Contains(cap) ? findings : caps, cap, $"attribute {r.Member} (trusted library {r.Assembly})  <-  {owner}  [reaches: {example}]");
            }
            // An assembly referenced only through types, signatures or attributes can still run
            // its code (type initializers, overrides, the module initializer). A trusted library
            // counts as analyzed only when every trusted version of it has a profile.
            foreach (var name in a.AssemblyRefs) {
                if (called.Contains(name)) continue;  // already reported for a member
                var kind = boundary.Resolve(name, own);
                if (kind == AssemblyKind.Unanalyzed || (kind == AssemblyKind.Trusted && !libraries.Profiled(name)))
                    Add(findings, "unanalyzed-call", $"{a.Name} references {name}{(kind == AssemblyKind.Trusted ? " (a trusted library without a profile for every version)" : "")}");
            }
        }
    }

    // A Harmony patch declared by attribute replaces or wraps the target's code, and sees and can
    // change its arguments: a prefix can redirect where a framework method writes, or what a game
    // method starts. The target is reached as TypeAccess says for a patch: what the patched member
    // can do that raises the tier (everything when the mod runs the target's code: a reverse patch
    // or a Harmony delegate), a framework type's capabilities by the policy's rules, the mod's own
    // code nothing more, anything else code that was not analyzed.
    static void PatchTargets(List<AssemblyFacts> analyzed, TypeAccess access, Dictionary<string, List<string>> findings,
        Dictionary<string, List<string>> caps, Action<string, string> cap) {
        foreach (var a in analyzed)
            foreach (var t in a.PatchTargets) {
                // Patching is what Harmony is for, whoever calls PatchAll (the mod or its loader).
                Add(caps, "code-patching", t.Detail);
                // Silence on purpose: no type named (with every attribute merged, see
                // AssemblyWalker.AddPatchTargets); the target then comes from a TargetMethod, which
                // the walker requires to be traced, or there is no target and nothing is patched.
                if (t.Type == null) continue;
                var members = t.Member != null ? new[] { t.Member } : null;
                foreach (var (c, detail) in access.Reach(t.Type, t.Assembly, members, t.Runs ? TypeUse.RunsPatch : TypeAccess.PatchUse(t.Effect), frameworkCaps: true, t.Detail))
                    cap(c, detail);
            }
    }

    // A transpiler is deep game access ("code-rewrite") only because what it can change is bounded to the
    // game method it rewrites. Rewriting anything else is Full access ("rewrite-outside-game"): framework
    // code (whose members the policy classifies by what they do as published), a trusted library (whose
    // profile, and the exemptions applied to it, assume its published code runs), the mod's own code
    // (whose analysis holds only as written), code that was not analyzed, or a target the check cannot
    // place. Targets: [HarmonyPatch] targets of a patch class with a transpiler, reverse patches when the
    // mod rewrites code (their stand-in can carry a transpiler), and what the walker records for
    // TargetMethod(s) and manual patches (see RewriteTarget).
    static void RewriteTargets(List<AssemblyFacts> analyzed, List<MethodFacts> methods, TypeAccess access, FieldProvenance provenance,
        bool rewrites, Dictionary<string, List<string>> findings) {
        const string Outside = "rewrite-outside-game";
        foreach (var t in analyzed.SelectMany(a => a.PatchTargets))
            if (t.Type != null && (t.Effect == PatchEffect.Rewrites || (t.Runs && rewrites)) && !access.IsGame(t.Type, t.Assembly, false))
                Add(findings, Outside, $"{t.Detail}  (a transpiler can rewrite it, and it is not the game's code)");
        foreach (var m in methods)
            foreach (var r in m.RewriteTargets.Where(r => rewrites || !r.IfRewrites)) {
                if (r.Node != null) {
                    var (held, why) = provenance.Held(r.Node);
                    if (why != null) { Add(findings, Outside, $"{r.Detail}  ({Nodes.Describe(r.Node)} {why})"); continue; }
                    foreach (var h in held.Where(h => !access.IsGame(h.Type, h.Assembly, h.Bounded)))
                        Add(findings, Outside, $"{r.Detail}  (it can hold a member of {h.Type}{(h.Assembly is { Length: > 0 } a ? " in " + a : "")}, which is not the game's code)");
                } else if (r.Type == null) {
                    Add(findings, Outside, r.Detail);
                } else if (!access.IsGame(r.Type, r.Assembly, r.Derived)) {
                    Add(findings, Outside, $"{r.Detail}{(r.Assembly is { Length: > 0 } a ? " in " + a : "")}  (not the game's code)");
                }
            }
    }

    static void Add(Dictionary<string, List<string>> d, string key, string evidence) {
        if (!d.TryGetValue(key, out var list)) d[key] = list = [];
        list.Add(evidence);
    }
}
