// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>
/// What each method of a set of assemblies can reach: its own capabilities and findings
/// ("seeds"), and those of every method it can call. Shared by the game-API map and the
/// trusted-library profiles. Nodes are method keys, so overloads share a node, and so do
/// same-named assemblies profiled together (several versions of one library).
/// </summary>
internal static class Reach {
    /// <summary>Capability or finding -> one example of what causes it.</summary>
    internal sealed class Caps : SortedDictionary<string, string> {
        public Caps() : base(StringComparer.Ordinal) { }
    }

    public static Caps Of(Dictionary<string, Caps> d, string key) {
        if (!d.TryGetValue(key, out var c)) d[key] = c = [];
        return c;
    }

    /// <summary>
    /// The capability seeds of each method, as the Evaluator counts them for a mod: label
    /// capabilities, those that raise the tier, and file access by path origin. A file capability found another
    /// way than a direct reference cannot be path-traced and counts as outside the game.
    /// Informational capabilities are left out: they never change a result. Without
    /// <paramref name="codeWrites"/>, writes into the mod's or the game's folders are left out too.
    /// </summary>
    /// <param name="assemblies">The assemblies whose methods are seeded.</param>
    /// <param name="policy">The policy whose capabilities count.</param>
    /// <param name="codeWrites">Keep writes into the mod's or the game's folders.</param>
    /// <param name="fieldsWritten">As in <see cref="FileAccess.Classify"/>.</param>
    /// <param name="reflected">As in <see cref="FileAccess.Classify"/>.</param>
    public static Dictionary<string, Caps> CapabilitySeeds(IReadOnlyCollection<AssemblyFacts> assemblies, Policy policy, bool codeWrites = true, Func<string, bool>? fieldsWritten = null,
        Func<string, bool>? reflected = null) {
        var seeds = new Dictionary<string, Caps>(StringComparer.Ordinal);
        foreach (var m in assemblies.SelectMany(a => a.Methods)) {
            var s = Of(seeds, m.Key);
            foreach (var e in m.Caps) {
                if (policy.FileKinds.TryGetValue(e.Cap, out var kind)) {
                    // Direct file operations are path-traced by FileAccess below.
                    if (e.Origin != Origin.Reference)
                        s.TryAdd(kind == FileOpKind.Write ? "file-write-outside" : "file-read-outside", e.Detail + "  (path not traceable)");
                    continue;
                }
                // Silence on purpose: informational capabilities have no label and no effect on a tier.
                if (policy.Informational.Contains(e.Cap)) continue;
                s.TryAdd(e.Cap, e.Detail);
            }
        }
        foreach (var (m, e) in FileAccess.Classify(assemblies, policy, fieldsWritten, reflected)) {
            // Silence on purpose when asked: see the caller.
            if (!codeWrites && e.Cap == "file-write-code") continue;
            Of(seeds, m.Key).TryAdd(e.Cap, e.Detail);
        }
        return seeds;
    }

    /// <summary>
    /// "Can reach" edges that are not calls in the IL: a virtual, abstract or interface method
    /// reaches each method of the same name in a type derived from or implementing its type (a
    /// call can dispatch there; explicit interface implementations "Ns.IFoo.M" count), and with
    /// <paramref name="typeInitializers"/>, every member of a type reaches the type's static
    /// constructor (the runtime runs it on first use). Types are matched by name across the set;
    /// over-approximation only adds edges.
    /// </summary>
    public static Dictionary<string, HashSet<string>> Edges(IReadOnlyCollection<AssemblyFacts> assemblies, bool typeInitializers) {
        var edges = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        void Edge(string from, string to) {
            if (!edges.TryGetValue(from, out var set)) edges[from] = set = new(StringComparer.Ordinal);
            set.Add(to);
        }
        // "asm|Type" -> (member name, key) of each method defined in it.
        var byType = new Dictionary<string, List<(string Member, string Key)>>(StringComparer.Ordinal);
        foreach (var a in assemblies)
            foreach (var m in a.Methods) {
                int sep = m.Key.LastIndexOf("::", StringComparison.Ordinal);
                if (sep < 0) continue;  // not a member key; no edges to add
                var type = m.Key[..sep];
                if (!byType.TryGetValue(type, out var list)) byType[type] = list = [];
                list.Add((m.Key[(sep + 2)..], m.Key));
            }
        foreach (var (type, members) in typeInitializers ? byType : []) {
            string cctor = type + "::.cctor";
            if (members.Any(x => x.Key == cctor))
                foreach (var (_, key) in members) if (key != cctor) Edge(key, cctor);
        }

        // Type name -> every "asm|Type" that derives from or implements it, directly or not.
        var supers = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var a in assemblies)
            foreach (var (t, s) in a.Types) {
                if (!supers.TryGetValue(t, out var list)) supers[t] = list = [];
                list.AddRange(s);
            }
        var derived = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var a in assemblies)
            foreach (var t in a.Types.Keys) {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var todo = new Stack<string>(a.Types[t]);
                while (todo.Count > 0) {
                    var s = todo.Pop();
                    if (!seen.Add(s)) continue;
                    if (!derived.TryGetValue(s, out var set)) derived[s] = set = new(StringComparer.Ordinal);
                    set.Add(a.Name + "|" + t);
                    if (supers.TryGetValue(s, out var up)) foreach (var u in up) todo.Push(u);
                }
            }
        foreach (var a in assemblies)
            foreach (var m in a.Methods.Where(m => m.IsVirtual)) {
                int sep = m.Name.LastIndexOf("::", StringComparison.Ordinal);
                if (sep < 0) continue;  // not a member name; nothing can override it
                string type = m.Name[..sep], member = m.Name[(sep + 2)..];
                if (!derived.TryGetValue(type, out var subs)) continue;  // nothing in the set derives from it
                foreach (var sub in subs)
                    if (byType.TryGetValue(sub, out var ms))
                        foreach (var (name, key) in ms)
                            if (name == member || name.EndsWith("." + member, StringComparison.Ordinal)) Edge(m.Key, key);
            }
        return edges;
    }

    /// <summary>
    /// Propagates seeds from callee to caller until nothing changes. <paramref name="edges"/> are
    /// extra "can reach" edges besides each method's callees (overrides, type initializers). Each
    /// capability keeps the example from where it was first found. <paramref name="exempt"/> maps
    /// a node key and a capability to the policy exemption that stops it there (see
    /// <see cref="Policy.Exemption"/>): the capability is neither kept at that node nor passed
    /// on from it; the exemption's label capability, if any, is passed on instead. Along the
    /// extra edges only capabilities that pass <paramref name="alongEdges"/> flow (all if null).
    /// </summary>
    public static Dictionary<string, Caps> Propagate(IReadOnlyCollection<MethodFacts> methods, Dictionary<string, Caps> seeds,
        IReadOnlyDictionary<string, HashSet<string>> edges, Func<string, bool>? alongEdges, Func<string, string, Policy.Exemption?> exempt) {
        var reach = new Dictionary<string, Caps>(StringComparer.Ordinal);
        bool AddAt(string key, Caps into, string cap, string detail) {
            if (exempt(key, cap) is not { } x) return into.TryAdd(cap, detail);
            // Silence on purpose: the policy exempts this capability here, with a reason.
            return x.As != null && into.TryAdd(x.As, $"{detail}  (counted as {x.As} by policy exemption)");
        }
        foreach (var m in methods) {
            var r = Of(reach, m.Key);
            if (seeds.TryGetValue(m.Key, out var s)) foreach (var (cap, d) in s) AddAt(m.Key, r, cap, d);
        }
        // callee -> (caller, whether the edge is an extra one)
        var callers = new Dictionary<string, Dictionary<string, bool>>(StringComparer.Ordinal);
        void Edge(string from, string to, bool extra) {
            if (!callers.TryGetValue(to, out var set)) callers[to] = set = new(StringComparer.Ordinal);
            // A call edge carries everything, so it wins over an extra edge between the same nodes.
            set[from] = set.TryGetValue(from, out var was) ? was && extra : extra;
        }
        foreach (var m in methods) foreach (var c in m.Callees) Edge(m.Key, c, false);
        foreach (var (from, tos) in edges) foreach (var to in tos) Edge(from, to, true);

        var queue = new Queue<string>(reach.Keys);
        while (queue.Count > 0) {
            var n = queue.Dequeue();
            if (reach[n].Count == 0 || !callers.TryGetValue(n, out var cs)) continue;
            foreach (var (c, extra) in cs) {
                // A caller outside the set (an edge from a key no method has) reaches nothing new.
                if (!reach.TryGetValue(c, out var rc)) continue;
                bool grew = false;
                foreach (var (cap, d) in reach[n]) {
                    // Silence on purpose: this kind of edge does not carry this capability (see alongEdges).
                    if (extra && alongEdges != null && !alongEdges(cap)) continue;
                    grew |= AddAt(c, rc, cap, d);
                }
                if (grew) queue.Enqueue(c);
            }
        }
        return reach;
    }
}
