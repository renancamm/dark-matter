// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>
/// Resolves reflection on values the walker traced to a node (see <see cref="Nodes"/>): a Type or
/// member field, a Type or member parameter, or what a method returns. A node's value is traced when
/// every value it is given, across all analyzed assemblies of a mod, is a type or member resolved
/// from a name (or another such node's value, or null): every store to a field, every argument a
/// call passes, every value a method returns. Running, creating, reading or writing through a node
/// that cannot be traced is unresolved reflection; one whose values are known only up to a type's
/// derived types (or an assembly) is bounded when that is the game's or the mod's code; one that can
/// be traced reaches the types it holds (<see cref="TypeAccess"/>). A member it holds was already
/// accounted for where it was looked up. Assembly names in node keys are compared ignoring case, as
/// the runtime binds them.
/// </summary>
internal sealed class FieldProvenance {
    readonly IReadOnlyCollection<MethodFacts> methods;
    readonly TypeAccess access;
    readonly HashSet<string> own;
    readonly Func<string, HashSet<string>, bool, (HashSet<HeldType> Held, string? Why)> trace;
    readonly Func<string, HashSet<string>, HashSet<string>?> names;
    readonly Func<string, bool> written;

    /// <summary>
    /// Whether fields of a type can be written through reflection: directly (FieldInfo.SetValue on a
    /// member of it, Harmony field references), through a traced node holding it, as one of the types
    /// a bounded write reaches, or by a write whose type is not known.
    /// </summary>
    public bool FieldsWritten(string type) => written(type);

    /// <summary>The types and members a node can hold, or why that cannot be traced.</summary>
    public (IReadOnlySet<HeldType> Held, string? Why) Held(string node) => trace(node, [], true);

    /// <param name="analyzed">The assemblies analyzed together (a mod, or a set of trusted libraries).</param>
    /// <param name="methods">Their methods.</param>
    /// <param name="access">What reaching a type held in a traced node can do, and where a type lives.</param>
    public FieldProvenance(IReadOnlyCollection<AssemblyFacts> analyzed, IReadOnlyCollection<MethodFacts> methods, TypeAccess access) {
        this.methods = methods;
        this.access = access;
        own = analyzed.Select(a => a.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var open = analyzed.SelectMany(a => a.OpenFields).Select(Nodes.Field).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var stores = new Dictionary<string, HashSet<HeldType>>(StringComparer.OrdinalIgnoreCase);
        var copies = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var untracked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var written = new HashSet<string>(StringComparer.Ordinal);  // types whose fields are written through reflection
        var byKey = new Dictionary<string, List<MethodFacts>>(StringComparer.OrdinalIgnoreCase);
        var strings = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in methods) {
            foreach (var (n, values) in m.StringArguments) Set(strings, n).UnionWith(values);
            foreach (var (f, held) in m.ReflectionStores) Set(stores, f).UnionWith(held);
            foreach (var (f, sources) in m.FieldCopies) Set(copies, f).UnionWith(sources);
            untracked.UnionWith(m.UntrackedStores);
            written.UnionWith(m.ReflectionFieldWrites);
            if (!byKey.TryGetValue(m.Key, out var list)) byKey[m.Key] = list = [];
            list.Add(m);
        }
        // The analyzed types with their base types and interfaces, to relate types by inheritance.
        var supers = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var a in analyzed)
            foreach (var (t, s) in a.Types) {
                if (!supers.TryGetValue(t, out var list)) supers[t] = list = [];
                list.AddRange(s);
            }

        // Methods of the analyzed code's own types that its reflection or its Harmony patches reach:
        // they can be called with any arguments (through Invoke's object[], a delegate made from a
        // MethodInfo, a patch that rewrites arguments). All of them when a type of the analyzed code
        // is reached by a name built at run time.
        var reflectedTypes = new HashSet<string>(StringComparer.Ordinal);
        bool anyOwnType = false;
        void Reflected(string type, string? assembly) {
            if (type == "*") { anyOwnType |= assembly != null && access.IsOwnAssembly(assembly); return; }
            if (access.IsOwn(type, assembly)) reflectedTypes.Add(type);
        }
        foreach (var m in methods) {
            foreach (var r in m.ReflectedTypes) Reflected(r.Type, r.Assembly);
            foreach (var b in m.BoundedReflection) Reflected(b.Type, b.Assembly);
        }
        foreach (var t in analyzed.SelectMany(a => a.PatchTargets).Where(t => t.Type != null)) Reflected(t.Type!, t.Assembly);

        // Whether a method is called by code the check does not see, with arguments of its choosing.
        string? CalledFromOutside(List<MethodFacts> ms) {
            if (ms.FirstOrDefault(x => x.CalledFromOutside != null) is { } m) return $"the method {m.CalledFromOutside}";
            if (anyOwnType) return "the method can be reached by reflection on a type found by a name built at run time";
            foreach (var x in ms) {
                int sep = x.Name.LastIndexOf("::", StringComparison.Ordinal);
                if (sep > 0 && Related(x.Name[..sep])) return "the method can be reached by reflection";
            }
            return null;
        }
        // A type reached by reflection, or one it derives from or that derives from it (reflection
        // on a type finds inherited members; a type known up to its derived types is any of them).
        bool Related(string type) {
            if (reflectedTypes.Count == 0) return false;
            if (Ancestors(type).Any(reflectedTypes.Contains)) return true;
            return reflectedTypes.Any(r => Ancestors(r).Contains(type));
        }
        IEnumerable<string> Ancestors(string type) {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var todo = new Stack<string>([type]);
            while (todo.Count > 0) {
                var t = todo.Pop();
                if (!seen.Add(t)) continue;
                yield return t;
                if (supers.TryGetValue(t, out var up)) foreach (var u in up) todo.Push(u);
            }
        }
        // Whether a type's fields are written through reflection: by its name, as one of the types
        // a bounded write reaches (a type it derives from, "T+"), or by a write whose type is unknown.
        bool Written(string type) =>
            written.Contains("*") || written.Contains(type) || Ancestors(type).Any(t => written.Contains(t + "+"));
        this.written = Written;

        // What a node can hold, or why it cannot be traced. checkWritten: also fail when a field's
        // own type has fields written through reflection, which bypasses its writers.
        (HashSet<HeldType> Held, string? Why) Trace(string node, HashSet<string> visiting, bool checkWritten) {
            // Members looked up on the types a node holds: those types, as members.
            if (node.StartsWith(Nodes.MemberPrefix, StringComparison.Ordinal)) {
                var (of, ofWhy) = Trace(node[Nodes.MemberPrefix.Length..], visiting, checkWritten);
                return ([.. of.Select(h => h with { Member = true })], ofWhy);
            }
            var held = new HashSet<HeldType>();
            if (!visiting.Add(node)) return (held, null);  // a cycle adds no new values
            var key = Nodes.Key(node);
            int bar = key.IndexOf('|', StringComparison.Ordinal), sep = key.IndexOf("::", StringComparison.Ordinal);
            if (bar < 0 || sep < bar || !own.Contains(key[..bar])) return (held, "belongs to code that was not analyzed");
            if (node.StartsWith(Nodes.ArgPrefix, StringComparison.Ordinal)) {
                if (!byKey.TryGetValue(key, out var ms)) return (held, "belongs to a method the check did not find");
                if (CalledFromOutside(ms) is { } why) return (held, $"can be any value: {why}");
                if (untracked.Contains(Nodes.Arg(key, -1))) return (held, "can be any value: the method is used as a delegate");
                if (untracked.Contains(node)) return (held, "is also given a value the check cannot trace");
            } else if (node.StartsWith(Nodes.ReturnPrefix, StringComparison.Ordinal)) {
                if (!byKey.TryGetValue(key, out var ms)) return (held, "belongs to a method the check did not find");
                if (ms.Any(x => x.Bodiless)) return (held, "comes from a method without a body the check can read");
                if (ms.Any(x => x.IsVirtual)) return (held, "can come from an override the check does not follow");
                if (untracked.Contains(node)) return (held, "includes a value the check cannot trace");
            } else {
                if (open.Contains(node)) return (held, "can be assigned by code outside the mod");
                if (untracked.Contains(node)) return (held, "is also assigned a value the check cannot trace");
                if (checkWritten && Written(key[(bar + 1)..sep])) return (held, "belongs to a type whose fields are written through reflection");
            }
            if (stores.TryGetValue(node, out var direct)) held.UnionWith(direct);
            if (copies.TryGetValue(node, out var sources))
                foreach (var g in sources) {
                    var (more, why) = Trace(g, visiting, checkWritten);
                    if (why != null) return (held, $"gets its value from {Nodes.Describe(g)}, which {why}");
                    held.UnionWith(more);
                }
            return (held, null);
        }
        trace = Trace;

        // The strings a string parameter is given, from every call: null when it can be any string
        // (the method can be called from outside, or is given one the check does not trace). A
        // method nobody calls looks nothing up.
        HashSet<string>? Names(string node, HashSet<string> visiting) {
            var result = new HashSet<string>(StringComparer.Ordinal);
            if (!visiting.Add(node)) return result;  // a cycle adds no new names
            var key = Nodes.Key(node);
            int bar = key.IndexOf('|', StringComparison.Ordinal);
            if (bar < 0 || !own.Contains(key[..bar]) || !byKey.TryGetValue(key, out var ms)) return null;
            if (CalledFromOutside(ms) != null || untracked.Contains(Nodes.Arg(key, -1))) return null;
            foreach (var v in strings.TryGetValue(node, out var values) ? values : []) {
                if (v.StartsWith('=')) { if (v.Length > 1) result.Add(v[1..]); continue; }  // null names nothing (the lookup throws)
                if (!v.StartsWith('@') || Names(v[1..], visiting) is not { } more) return null;
                result.UnionWith(more);
            }
            return result;
        }
        names = Names;

        // Types the traced nodes hold are reached by reflection too (see above).
        foreach (var m in methods)
            foreach (var r in m.FieldReflection)
                if (Trace(r.Node, [], false) is { Why: null } t)
                    foreach (var h in t.Held.Where(h => !h.Member)) Reflected(h.Type, h.Assembly);

        // Writes through a traced node reach the fields of the types it holds. An untraced one
        // is already unresolved in Resolve.
        foreach (var m in methods)
            foreach (var r in m.FieldReflection.Where(r => r.WritesFields))
                if (Trace(r.Node, [], false) is { Why: null } t)
                    written.UnionWith(t.Held.Select(h => h.Bounded ? (h.Type == "*" ? "*" : h.Type + "+") : h.Type));
    }

    /// <summary>
    /// The members a lookup reaches: <paramref name="members"/>, or, for one whose member name is a
    /// string parameter (<paramref name="nameNode"/>), the members named by every string that
    /// parameter is given (null, any member, when that can be any string).
    /// </summary>
    public IReadOnlyList<string>? Members(IReadOnlyList<string>? members, string? nameNode, string? lookup) {
        if (nameNode == null || lookup == null) return members;
        if (names(nameNode, []) is not { } given) return members;
        var reached = new List<string>();
        foreach (var n in given.Order(StringComparer.Ordinal)) {
            if (ReflectionApis.MemberNames(lookup, n) is not { } m) return null;
            reached.AddRange(m);
        }
        return reached;
    }

    /// <summary>Resolves the reflection the walker traced to nodes.</summary>
    /// <param name="unresolved">Reflection through nodes that cannot be traced, per method.</param>
    /// <param name="bounded">Reflection through nodes traced only to the game's or the mod's types, per method.</param>
    /// <param name="caps">Capabilities and findings reached through traced nodes, per method.</param>
    public void Resolve(List<(MethodFacts Method, string Detail)> unresolved, List<(MethodFacts Method, string Detail)> bounded, List<(MethodFacts Method, Evidence Evidence)> caps) {
        (HashSet<HeldType> Held, string? Why) Trace(string node, HashSet<string> visiting, bool checkWritten) => trace(node, visiting, checkWritten);
        foreach (var m in methods) {
            foreach (var r in m.FieldReflection) {
                var (held, why) = Trace(r.Node, [], true);
                if (why != null) {
                    // A lookup alone runs nothing; what it finds is checked where it is used.
                    if (r.Invokes) unresolved.Add((m, $"{r.Detail}  ({Nodes.Describe(r.Node)} {why})"));
                    continue;
                }
                foreach (var h in held) {
                    // A type or member known only up to its derived types (or its assembly): bounded
                    // when that is the game's or the mod's code, unresolved otherwise.
                    if (h.Bounded && r.Invokes) {
                        var d = $"{r.Detail}  ({Nodes.Describe(r.Node)} holds {(h.Member ? "a member of " : "")}{Bound(h)})";
                        if (access.Bounded(h.Type, h.Assembly)) bounded.Add((m, d));
                        else unresolved.Add((m, d + ", which is not the game's or the mod's code"));
                    }
                    // Silence on purpose for a member: it was accounted for where it was looked up.
                    if (h.Member || h.Type == "*") continue;
                    foreach (var (cap, detail) in access.Reach(h.Type, h.Assembly, Members(r.Members, r.NameNode, r.Lookup), TypeUse.Reflection, frameworkCaps: true, $"{h.Type}  (via {Nodes.Describe(r.Node)})  <-  {m.Name}"))
                        caps.Add((m, new(cap, detail, Origin.Reflection)));
                }
            }
            // A Type or member handed to another assembly's field is used by code that was not
            // analyzed, so it must be traced too (bounded at most).
            bool External(string node) => node.StartsWith(Nodes.FieldPrefix, StringComparison.Ordinal)
                && Nodes.Key(node) is var k && !own.Contains(k[..Math.Max(0, k.IndexOf('|', StringComparison.Ordinal))]);
            foreach (var f in m.UntrackedStores.Where(External))
                unresolved.Add((m, $"a type or member not traced to a name is stored into {Nodes.Describe(f)}, which belongs to code that was not analyzed  <-  {m.Name}"));
            foreach (var (f, held) in m.ReflectionStores.Where(kv => External(kv.Key)))
                foreach (var h in held.Where(h => h.Bounded)) {
                    var d = $"{(h.Member ? "a member of " : "")}{Bound(h)} is stored into {Nodes.Describe(f)}, which belongs to code that was not analyzed  <-  {m.Name}";
                    if (access.Bounded(h.Type, h.Assembly)) bounded.Add((m, d));
                    else unresolved.Add((m, d));
                }
            foreach (var (f, sources) in m.FieldCopies.Where(kv => External(kv.Key)))
                foreach (var g in sources) {
                    var (held, why) = Trace(g, [], true);
                    if (why != null) {
                        unresolved.Add((m, $"{Nodes.Describe(g)} is stored into {Nodes.Describe(f)}, which belongs to code that was not analyzed, and {why}  <-  {m.Name}"));
                        continue;
                    }
                    foreach (var h in held.Where(h => h.Bounded)) {
                        var d = $"{Nodes.Describe(g)} is stored into {Nodes.Describe(f)}, which belongs to code that was not analyzed, and holds {(h.Member ? "a member of " : "")}{Bound(h)}  <-  {m.Name}";
                        if (access.Bounded(h.Type, h.Assembly)) bounded.Add((m, d));
                        else unresolved.Add((m, d));
                    }
                }
        }
    }

    // How a bounded type reads in evidence.
    static string Bound(HeldType h) => h.Type == "*" ? $"a type of {h.Assembly}" : $"{h.Type} or a type derived from it";

    static HashSet<T> Set<T>(Dictionary<string, HashSet<T>> d, string key) {
        if (!d.TryGetValue(key, out var set)) d[key] = set = [];
        return set;
    }
}
