// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>
/// What each member of one trusted library file can reach, keyed by the file's SHA-256.
/// </summary>
/// <param name="Name">The allowlist name (file name without extension).</param>
/// <param name="Assembly">The assembly name read from the file.</param>
/// <param name="Types">Every type the file defines, with its base type and interfaces.</param>
/// <param name="Forwarded">Types the file forwards to another assembly.</param>
/// <param name="Members">Every method and field, "Namespace.Type::Member" (overloads merged), with
/// the capabilities and findings it reaches and one example of each.</param>
internal sealed record LibraryProfile(
    string Name,
    string Assembly,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Types,
    IReadOnlySet<string> Forwarded,
    IReadOnlyDictionary<string, Reach.Caps> Members) {

    /// <summary>
    /// Profiles a set of trusted library files together, so calls between them are followed.
    /// Unlike the game-API map, findings are kept (Full-access ones): a library is
    /// third-party code trusted to be the build its author published, not to be harmless, so a
    /// mod calling a member gets everything that member can reach, less what the policy's
    /// <c>libraries.exempt</c> stops.
    /// </summary>
    /// <param name="files">Analyzed trusted files with their allowlist names.</param>
    /// <param name="policy">The policy whose rules produced the files' facts.</param>
    /// <param name="boundary">Resolves references that leave the set (game, framework, anything else).</param>
    /// <param name="gameApi">The game-API map, for reflection on game types.</param>
    /// <param name="gameTypes">The game's types, from the game profile; null without one.</param>
    public static List<(string Sha256, LibraryProfile Profile)> Build(IReadOnlyList<(AssemblyFacts Facts, string Name)> files, Policy policy, Boundary boundary,
        IReadOnlyDictionary<string, string[]> gameApi, IReadOnlySet<string>? gameTypes) {
        var set = files.Select(f => f.Facts).ToList();
        var methods = set.SelectMany(a => a.Methods).ToList();
        var own = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (f, name) in files) { own.Add(f.Name); own.Add(name); }
        // Reflection reaches what the types it resolves can do, by where they live; calls between
        // the libraries profiled together are followed, so they are this set's own types.
        var access = new TypeAccess(policy, boundary, own, set.SelectMany(a => a.Types.Keys).ToHashSet(StringComparer.Ordinal), TrustedLibraries.None, gameApi, gameTypes);
        var provenance = new FieldProvenance(set, methods, access);
        var seeds = Reach.CapabilitySeeds(set, policy, fieldsWritten: provenance.FieldsWritten);
        void Seed(MethodFacts m, string cap, string detail) {
            var s = Reach.Of(seeds, m.Key);
            if (policy.FileKinds.TryGetValue(cap, out var kind))
                s.TryAdd(kind == FileOpKind.Write ? "file-write-outside" : "file-read-outside", detail + "  (path not traceable)");
            else if (!policy.Informational.Contains(cap))
                s.TryAdd(cap, detail);
        }
        foreach (var m in methods)
            foreach (var r in m.ReflectedTypes)
                foreach (var (cap, detail) in access.Reach(r.Type, r.Assembly, provenance.Members(r.Members, r.NameNode, r.Lookup), r.PatchTarget ? TypeAccess.PatchUse(r.Patch) : TypeUse.Reflection, frameworkCaps: false, r.Detail))
                    Seed(m, cap, detail);
        var pointerFields = set.SelectMany(a => a.PointerFields).ToHashSet(StringComparer.Ordinal);
        // A transpiler that rewrites anything but the game's code is Full access, as for a mod (see
        // Evaluator.RewriteTargets); Harmony's own patching members are exempt (libraries.exempt).
        bool rewrites = set.SelectMany(a => a.Caps).Concat(methods.SelectMany(m => m.Caps)).Any(e => e.Cap == "code-rewrite");
        foreach (var m in methods)
            foreach (var r in m.RewriteTargets.Where(r => rewrites || !r.IfRewrites)) {
                string? why = null;
                if (r.Node != null) {
                    var (held, untraced) = provenance.Held(r.Node);
                    why = untraced != null ? $"{Nodes.Describe(r.Node)} {untraced}"
                        : held.FirstOrDefault(h => !access.IsGame(h.Type, h.Assembly, h.Bounded)) is { Type: not null } h ? $"it can hold a member of {h.Type}, which is not the game's code" : null;
                } else if (r.Type == null || !access.IsGame(r.Type, r.Assembly, r.Derived)) {
                    why = "not the game's code";
                }
                if (why != null) Reach.Of(seeds, m.Key).TryAdd("rewrite-outside-game", $"{r.Detail}  ({why})");
            }

        foreach (var a in set) {
            // Assembly-level findings apply to every member: native or precompiled code means the
            // IL read may not be what runs. Raw-memory markers (unsafe code enabled, pointer
            // fields) are covered per method instead: pointer locals, signatures and stores are
            // checked in each method, and pointer fields where they are used, below.
            var whole = a.Caps.Where(e => e.Cap != "raw-memory" && !policy.Informational.Contains(e.Cap)).ToList();
            // An assembly referenced only through types can still run code; which member leads
            // there is not known, so every member gets it.
            var unanalyzedRefs = a.AssemblyRefs.Where(n => !own.Contains(n) && boundary.Resolve(n, own) == AssemblyKind.Unanalyzed).ToList();
            foreach (var m in a.Methods) {
                var s = Reach.Of(seeds, m.Key);
                foreach (var e in whole) s.TryAdd(e.Cap, e.Detail);
                foreach (var n in unanalyzedRefs) s.TryAdd("unanalyzed-call", $"{a.Name} references {n}");
                foreach (var d in m.UnresolvedReflection) s.TryAdd("unresolved-reflection", d);
                foreach (var b in m.BoundedReflection) s.TryAdd(access.Bounded(b.Type, b.Assembly) ? "bounded-reflection" : "unresolved-reflection", b.Detail);
                foreach (var d in m.ComActivation) s.TryAdd("com-activation", d);
                if (m.DecodeFailed) s.TryAdd("decode-failure", m.Name);
                foreach (var f in m.FieldLoads.Concat(m.FieldStores).Where(pointerFields.Contains))
                    s.TryAdd("raw-memory", $"pointer field {f[(f.IndexOf('|', StringComparison.Ordinal) + 1)..]} used in {m.Name}");
                foreach (var r in m.ExternalRefs) {
                    switch (boundary.Resolve(r.Assembly, own)) {
                        case AssemblyKind.Unanalyzed:
                        case AssemblyKind.Trusted:  // a trusted library outside this set was not profiled with it
                            s.TryAdd("unanalyzed-call", $"{r.Member} in {(r.Assembly.Length > 0 ? r.Assembly : "an assembly the check cannot determine")}  <-  {m.Name}");
                            break;
                        case AssemblyKind.Framework when !r.Classified:
                            s.TryAdd("unclassified-reference", $"{r.Member}  <-  {m.Name}");
                            break;
                    }
                }
            }
        }
        var unresolved = new List<(MethodFacts, string)>();
        var bounded = new List<(MethodFacts, string)>();
        var fieldCaps = new List<(MethodFacts, Evidence)>();
        provenance.Resolve(unresolved, bounded, fieldCaps);
        foreach (var (m, d) in unresolved) Reach.Of(seeds, m.Key).TryAdd("unresolved-reflection", d);
        foreach (var (m, d) in bounded) Reach.Of(seeds, m.Key).TryAdd("bounded-reflection", d);
        foreach (var (m, e) in fieldCaps) Seed(m, e.Cap, e.Detail);

        // Node keys start with the assembly name; exemptions name the library by allowlist name.
        var libraryOf = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (f, name) in files) libraryOf.TryAdd(f.Name, name);
        var reach = Reach.Propagate(methods, seeds, Reach.Edges(set, typeInitializers: true), null, (key, cap) => {
            int bar = key.IndexOf('|', StringComparison.Ordinal);
            return bar > 0 && libraryOf.TryGetValue(key[..bar], out var lib) ? policy.ExemptionFor(lib, key[(bar + 1)..], cap) : null;
        });
        var result = new List<(string, LibraryProfile)>();
        foreach (var (f, name) in files) {
            var members = new SortedDictionary<string, Reach.Caps>(StringComparer.Ordinal);
            foreach (var m in f.Methods) {
                var into = members.TryGetValue(m.Name, out var c) ? c : members[m.Name] = [];
                foreach (var (cap, d) in reach[m.Key]) into.TryAdd(cap, d);
            }
            // Touching a field runs the type's static constructor.
            foreach (var field in f.Fields) {
                var into = members.TryGetValue(field, out var c) ? c : members[field] = [];
                int sep = field.LastIndexOf("::", StringComparison.Ordinal);
                if (sep >= 0 && reach.TryGetValue(f.Name + "|" + field[..sep] + "::.cctor", out var cctor))
                    foreach (var (cap, d) in cctor) into.TryAdd(cap, d);
            }
            var types = f.Types.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)kv.Value, StringComparer.Ordinal);
            result.Add((f.Sha256!, new LibraryProfile(name, f.Name, types, f.ForwardedTypes.ToHashSet(StringComparer.Ordinal), members)));
        }
        return result;
    }

    /// <summary>
    /// What a call to <paramref name="member"/> reaches in this file: the member itself or one it
    /// inherits from a base type in the file. Null when there is no such member; then
    /// <paramref name="outside"/> says whether it could be inherited from a type outside the file.
    /// </summary>
    public Reach.Caps? Find(string member, out bool outside) {
        outside = false;
        int sep = member.LastIndexOf("::", StringComparison.Ordinal);
        if (sep < 0) return null;  // not a member name: found nowhere, so the caller fails closed
        string name = member[(sep + 2)..];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var todo = new Queue<string>([member[..sep]]);
        while (todo.Count > 0) {
            var t = todo.Dequeue();
            if (!seen.Add(t)) continue;
            if (Members.TryGetValue(t + "::" + name, out var caps)) return caps;
            if (!Types.TryGetValue(t, out var supers)) {
                // The root types every class and struct derive from add no members a call could
                // reach by naming this type that would not name them directly.
                if (seen.Count > 1 && t is not ("System.Object" or "System.ValueType" or "System.Enum")) outside = true;
                continue;
            }
            foreach (var s in supers) todo.Enqueue(s);
        }
        return null;
    }
}

/// <summary>
/// The library profiles available to an analysis, and the allowlist hashes behind each trusted
/// library name. A mod's call into a trusted library may run any trusted version of it (the
/// loader decides which copy is loaded), so the call reaches the union of every version's member.
/// </summary>
internal sealed class TrustedLibraries(IReadOnlyDictionary<string, IReadOnlyList<string>> hashesByName, IReadOnlyDictionary<string, LibraryProfile> profiles) {
    /// <summary>Why <see cref="Lookup"/> found nothing when no profiled version has the member.</summary>
    public const string NoSuchMember = "no profiled trusted version has this member";

    /// <summary>No trusted library (for a library profile, which profiles them together).</summary>
    public static TrustedLibraries None { get; } = new(new Dictionary<string, IReadOnlyList<string>>(), new Dictionary<string, LibraryProfile>());

    /// <summary>Names of the trusted libraries with a profiled version that defines <paramref name="type"/>.</summary>
    public IEnumerable<string> Defining(string type) =>
        hashesByName.Where(kv => kv.Value.Any(h => profiles.TryGetValue(h, out var p) && p.Types.ContainsKey(type))).Select(kv => kv.Key);

    /// <summary>
    /// What reflection on <paramref name="type"/> of a trusted library can reach: every member of the
    /// type and of its base types in the file, across every trusted version; or null and why that
    /// cannot be known (no profile for a version, a base type outside the file, no version has the type).
    /// </summary>
    public Reach.Caps? LookupType(string library, string type, out string why) {
        why = "";
        if (!hashesByName.TryGetValue(library, out var hashes) || hashes.Count == 0) { why = $"no managed trusted file is named {library}"; return null; }
        var union = new Reach.Caps();
        bool found = false;
        foreach (var h in hashes) {
            if (!profiles.TryGetValue(h, out var p)) { why = $"no library profile for trusted file {h[..12]}"; return null; }
            if (p.Forwarded.Contains(type)) { why = $"{type} is forwarded to another assembly in trusted file {h[..12]}"; return null; }
            var todo = new Queue<string>([type]);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (todo.Count > 0) {
                var t = todo.Dequeue();
                if (!seen.Add(t)) continue;
                if (!p.Types.TryGetValue(t, out var supers)) {
                    // Framework base types and interfaces add framework members, which the policy
                    // classifies by name; any other type outside the file adds code not profiled here.
                    if (seen.Count > 1 && !t.StartsWith("System.", StringComparison.Ordinal)) { why = $"{type} derives from {t}, outside trusted file {h[..12]}"; return null; }
                    // Silence on purpose: this version does not define the type, so the lookup fails there.
                    continue;
                }
                found = true;
                foreach (var (member, caps) in p.Members)
                    if (member.StartsWith(t + "::", StringComparison.Ordinal) || member.StartsWith(t + "/", StringComparison.Ordinal))
                        foreach (var (cap, d) in caps) union.TryAdd(cap, d);
                foreach (var s in supers) todo.Enqueue(s);
            }
        }
        if (!found) { why = "no profiled trusted version has this type"; return null; }
        return union;
    }

    /// <summary>Whether every trusted version of <paramref name="library"/> has a profile.</summary>
    public bool Profiled(string library) =>
        hashesByName.TryGetValue(library, out var hashes) && hashes.Count > 0 && hashes.All(profiles.ContainsKey);

    /// <summary>
    /// The capabilities and findings a call to <paramref name="member"/> of a trusted library
    /// reaches, across every trusted version; or null and why that cannot be known (no profile for
    /// a version, a forwarded type, a member no profiled version has). Unknown is code that was not analyzed (not fully checked).
    /// </summary>
    public Reach.Caps? Lookup(string library, string member, out string why) {
        why = "";
        if (!hashesByName.TryGetValue(library, out var hashes) || hashes.Count == 0) { why = $"no managed trusted file is named {library}"; return null; }
        var union = new Reach.Caps();
        bool found = false;
        int sep = member.LastIndexOf("::", StringComparison.Ordinal);
        string type = sep >= 0 ? member[..sep] : member;
        foreach (var h in hashes) {
            if (!profiles.TryGetValue(h, out var p)) { why = $"no library profile for trusted file {h[..12]}"; return null; }
            if (p.Find(member, out bool outside) is { } caps) {
                found = true;
                foreach (var (cap, d) in caps) union.TryAdd(cap, d);
                continue;
            }
            if (p.Forwarded.Contains(type)) { why = $"{type} is forwarded to another assembly in trusted file {h[..12]}"; return null; }
            if (outside) { why = $"may be inherited from a type outside trusted file {h[..12]}"; return null; }
            // Silence on purpose: this version has no such member, so the call fails there
            // (MissingMemberException or TypeLoadException) and runs none of its code.
        }
        if (!found) { why = NoSuchMember; return null; }
        return union;
    }
}
