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
    readonly Func<string, bool> reflected;

    // How ReflectionApis.MemberNames names the methods of a property or event a lookup finds by its name.
    static readonly string[] AccessorPrefixes = ["get_", "set_", "add_", "remove_", "raise_"];

    /// <summary>
    /// Whether fields of a type can be written through reflection: directly (FieldInfo.SetValue on a
    /// member of it, Harmony field references), through a traced node holding it, as one of the types
    /// a bounded write reaches, or by a write whose type is not known.
    /// </summary>
    public bool FieldsWritten(string type) => written(type);

    /// <summary>
    /// Whether reflection on the analyzed code's own types can reach the method <paramref name="key"/> (a node
    /// key, "Assembly|Type::Name"): a lookup can return it (see the reach below), or a type of the analyzed code
    /// is found by a name built at run time. It is then called with any arguments (MethodBase.Invoke).
    /// </summary>
    public bool ReachedByReflection(string key) => reflected(key);

    /// <summary>The types and members a node can hold, or why that cannot be traced.</summary>
    public (IReadOnlySet<HeldType> Held, string? Why) Held(string node) => trace(node, [], true);

    /// <param name="analyzed">The assemblies analyzed together (a mod, or a set of trusted libraries).</param>
    /// <param name="methods">Their methods.</param>
    /// <param name="access">What reaching a type held in a traced node can do, and where a type lives.</param>
    /// <param name="gameMembers">The declared types of the game's members, from the game profile; null without one.</param>
    public FieldProvenance(IReadOnlyCollection<AssemblyFacts> analyzed, IReadOnlyCollection<MethodFacts> methods, TypeAccess access, GameTypes? gameMembers = null) {
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
        var called = new HashSet<string>(StringComparer.OrdinalIgnoreCase);  // methods some analyzed code calls
        // Harmony patches applied by hand, by patch method (R3): what each Harmony.Patch call that hands the method over patches.
        var manual = new Dictionary<string, List<ManualPatch>>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in methods) {
            called.UnionWith(m.Callees);
            foreach (var p in m.ManualPatches) {
                if (!manual.TryGetValue(p.Method, out var applied)) manual[p.Method] = applied = [];
                applied.Add(p);
            }
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
        // Per type, the member names a lookup on it can return (null: any member), as
        // ReflectionApis.MemberNames gives them and ReflectionApis.MemberMatches compares them (ignoring
        // case; a name ending in '*' is a prefix; "/Name" is every member of a nested type of that name).
        // H7 ("F1"): before, every method of a reached type counted, whatever the lookup could return.
        var reach = new Dictionary<string, HashSet<string>?>(StringComparer.Ordinal);
        // The same, without the lookups that only handed a method of the mod to Harmony.Patch as a patch method
        // (ReflectedType.Handoff, R3): nothing but Harmony got hold of the method there, so such a lookup is no way
        // to call it with an instance of the mod's choosing. Only the instance Harmony passes is decided by this one.
        var reachOther = new Dictionary<string, HashSet<string>?>(StringComparer.Ordinal);
        // A handoff counts as one only when the method it names is declared by the type it names (the method the
        // lookup finds, whose key the ManualPatch carries): a name only a base type has finds that type's method.
        bool Excused(ReflectedType r) => r.Handoff && r.NameNode == null && r.Assembly != null && r.Members is { Count: > 0 } named
            && named.All(n => byKey.ContainsKey($"{r.Assembly}|{r.Type}::{n}"));
        // Lookups whose member name is a string parameter: they reach what every call passes, which
        // depends on which methods are reached (below, to a fixpoint).
        var pending = new HashSet<(string Type, string NameNode, string Lookup)>();
        // The properties and events each method belongs to, by the metadata (an accessor need not be
        // named get_X or set_X). If a type's could not be read, any lookup reaches any member.
        var accessors = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var a in analyzed)
            foreach (var (m, of) in a.Accessors) Set(accessors, m).UnionWith(of);
        bool coarse = analyzed.Any(a => a.AccessorsUnread.Count > 0);
        bool anyOwnType = false;
        // Records a lookup on a type; true when that reaches something it did not before. derived: the
        // type or any type derived from it (the run-time type of a value of that declared type): the
        // analyzed code's types that derive from it are reached too, also when it is not one of that code's
        // own (a game type the mod derives from, found through GetType() of a game-typed value: H7b), by
        // the rule in Related below (a type is reached when a type it derives from is).
        bool Reflected(string type, string? assembly, IReadOnlyList<string>? members = null, string? nameNode = null, string? lookup = null, bool derived = false, bool excused = false) {
            if (type == "*") {
                bool before = anyOwnType;
                anyOwnType |= assembly != null && access.IsOwnAssembly(assembly);
                return anyOwnType != before;
            }
            if (!derived && !access.IsOwn(type, assembly)) return false;
            if (members == null && nameNode != null && lookup != null && !coarse) {
                bool added = pending.Add((type, nameNode, lookup));
                reachOther.TryAdd(type, new(StringComparer.Ordinal));
                return reach.TryAdd(type, new(StringComparer.Ordinal)) || added;
            }
            return AddReach(type, members, excused);
        }
        bool AddReach(string type, IReadOnlyList<string>? members, bool excused = false) {
            if (!excused) AddTo(reachOther, type, members);
            return AddTo(reach, type, members);
        }
        bool AddTo(Dictionary<string, HashSet<string>?> map, string type, IReadOnlyList<string>? members) {
            if (members == null || coarse) {
                if (map.TryGetValue(type, out var cur) && cur == null) return false;
                map[type] = null;
                return true;
            }
            if (!map.TryGetValue(type, out var set)) map[type] = set = new(StringComparer.Ordinal);
            if (set == null) return false;
            bool changed = false;
            foreach (var n in members) changed |= set.Add(n);
            return changed;
        }
        foreach (var m in methods) {
            foreach (var r in m.ReflectedTypes) Reflected(r.Type, r.Assembly, r.Members, r.NameNode, r.Lookup, excused: Excused(r));
            foreach (var b in m.BoundedReflection) Reflected(b.Type, b.Assembly, derived: true);
        }
        foreach (var t in analyzed.SelectMany(a => a.PatchTargets).Where(t => t.Type != null)) Reflected(t.Type!, t.Assembly, t.Member is { } pm ? [pm] : null);

        reflected = key => byKey.TryGetValue(key, out var rms) && (anyOwnType || rms.Any(x => Reached(x.Name, reach)));
        // Whether a method is called by code the check does not see, with arguments of its choosing. lookups: the
        // reflection reach that counts (all of it, or without the lookups that only handed a method to Harmony.Patch).
        string? CalledFromOutside(List<MethodFacts> ms, Dictionary<string, HashSet<string>?> lookups) {
            if (ms.FirstOrDefault(x => x.CalledFromOutside != null) is { } m) return $"the method {m.CalledFromOutside}";
            if (anyOwnType) return "the method can be reached by reflection on a type found by a name built at run time";
            foreach (var x in ms) if (Reached(x.Name, lookups)) return "the method can be reached by reflection";
            return null;
        }
        // Whether a method of the analyzed code that Harmony may call as a patch can replace what Harmony passes other
        // patch methods for `passed` (PatchParameter): through a by-reference parameter, which Harmony gives the address
        // of the original's argument, instance or result whatever type the parameter declares. Harmony may call a
        // method that code outside the analysis can call (a patch method by name or attribute, a public one), that is
        // handed to Harmony.Patch, taken as a delegate or reached by reflection. The method named is why.
        string? Replaced(string passed, IReadOnlyDictionary<string, string>? original = null, string? method = null) {
            int? Position(string name) => original != null && method != null ? MemberTypes.Position(original.GetValueOrDefault(MemberTypes.ParameterPositionKey(method, name))) : null;
            foreach (var m in methods) {
                if (!m.PatchReplaces.Any(r => PatchParameter.Replaces(r, passed, Position))) continue;
                if (m.CalledFromOutside != null || anyOwnType || manual.ContainsKey(m.Key) || untracked.Contains(Nodes.Arg(m.Key, -1)) || Reached(m.Name, reach)) return m.Name;
            }
            return null;
        }
        // The declared members of a type of the analyzed code or of the game (see AssemblyFacts.MemberTypes), for
        // typing what Harmony passes from an original's signature (R10); null for any other type, a type two analyzed
        // assemblies of one name define, or a type found by name that is not the game's alone.
        IReadOnlyDictionary<string, string>? DeclaredMembers(string type, string? assembly) {
            if (assembly != null && own.Contains(assembly)) {
                var defining = analyzed.Where(a => string.Equals(a.Name, assembly, StringComparison.OrdinalIgnoreCase) && a.MemberTypes.ContainsKey(type)).ToList();
                return defining.Count == 1 ? defining[0].MemberTypes[type] : null;
            }
            return gameMembers != null && access.IsGame(type, assembly, derived: false) ? gameMembers.Members.GetValueOrDefault(type) : null;
        }
        // The members a Harmony.Patch call patches with a method (R3): each must be one method found by a constant
        // name on exactly one type, which that type alone declares (MemberValue.Sole); a type found by name must be
        // the game's alone (as for TypedByName). Null with why when the check cannot tell.
        (List<HeldType>? Originals, string? Why) PatchedBy(ManualPatch p, HashSet<string> visiting, bool checkWritten) {
            IEnumerable<HeldType> originals;
            if (p.Originals != null) originals = p.Originals;
            else if (p.OriginalNode != null) {
                var (of, ofWhy) = Trace(p.OriginalNode, visiting, checkWritten);
                if (ofWhy != null) return (null, $"Harmony.Patch applies the patch method to {Nodes.Describe(p.OriginalNode)}, which {ofWhy}");
                originals = of;
            } else return (null, "Harmony.Patch applies the patch method to a member the check does not trace");
            var result = new List<HeldType>();
            foreach (var h in originals) {
                if (!h.Member || h.Bounded || h.Type == "*" || h.Value is not { Kind: MemberKind.Method, Sole: not null })
                    return (null, $"Harmony.Patch applies the patch method to a member of {h.Type} that the check cannot tell is declared by that type alone");
                if (h.Assembly == null && !access.IsGame(h.Type, null, derived: false))
                    return (null, $"Harmony.Patch applies the patch method to a member of {h.Type}, a type found by name that is not the game's alone");
                result.Add(h);
            }
            return (result, null);
        }
        // Whether a lookup can return the method "Type::Name": by its name, or by the name of a property
        // or event it belongs to (whatever the method is called).
        bool Reached(string method, Dictionary<string, HashSet<string>?> reach) {
            if (reach.Count == 0) return false;
            int sep = method.LastIndexOf("::", StringComparison.Ordinal);
            if (sep <= 0) return false;
            var simple = method[(sep + 2)..];
            if (Related(method[..sep], n => ReflectionApis.MemberMatches(n, simple), reach)) return true;
            if (accessors.TryGetValue(method, out var of))
                foreach (var o in of) {
                    int osep = o.LastIndexOf("::", StringComparison.Ordinal);
                    var name = o[(osep + 2)..];
                    if (Related(o[..osep], n => ReflectionApis.MemberMatches(n, name) || AccessorPrefixes.Any(p => ReflectionApis.MemberMatches(n, p + name)), reach))
                        return true;
                }
            return false;
        }
        // A type reached by reflection, or one it derives from or that derives from it (reflection
        // on a type finds inherited members; a type known up to its derived types is any of them), or a
        // type nested in one of those: the walker counts a nested type found by GetNestedType(s) or
        // GetMember as the type it was found from (H3, H1a-review H5), so a name looked up on the outer
        // type is one on the nested type too, and "/Name" reaches every member of the nested type Name
        // (and of the types nested in it). names: whether a reached name finds the member.
        bool Related(string type, Func<string, bool> names, Dictionary<string, HashSet<string>?> reach) {
            for (var t = type; ; t = t[..t.LastIndexOf('/')]) {
                // The nested type, under t, that holds the member ("" for a member of t itself).
                var below = t.Length < type.Length ? type[(t.Length + 1)..] : "";
                var segment = below.Split('/')[0];
                bool Hit(string r) => reach.TryGetValue(r, out var set) && (set == null || set.Any(n =>
                    n.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal)
                        ? segment.Length > 0 && ReflectionApis.MemberMatches(n[ReflectionApis.NestedPrefix.Length..], segment)
                        : names(n)));
                if (Ancestors(t).Any(Hit)) return true;
                if (reach.Keys.Any(r => Hit(r) && Ancestors(r).Contains(t))) return true;
                if (t.LastIndexOf('/') <= 0) return false;
            }
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
                return ([.. of.Select(h => h with { Member = true, Value = null })], ofWhy);
            }
            var held = new HashSet<HeldType>();
            // The declared types of the members a node holds, or the run-time types of values read through them (D5,
            // D6): known for a member found by a constant name on exactly one type whose declared type the walker
            // knew (HeldType.Value), of the kind the read is made on. Anything else it holds is not followed.
            if (Nodes.TypeOfParts(node) is var (kind, value, source)) {
                var (of, ofWhy) = Trace(source, visiting, checkWritten);
                if (ofWhy != null) return (held, $"is not known: {Nodes.Describe(source)} {ofWhy}");
                foreach (var h in of) {
                    if (!h.Member || h.Bounded || h.Value is not { Typed: true } v || v.Kind != kind)
                        return (held, $"is not known: {Nodes.Describe(source)} can hold a member whose declared type the check does not know");
                    held.Add(new(v.Type, v.Asm, false, Bounded: value));
                }
                return (held, null);
            }
            if (!visiting.Add(node)) return (held, null);  // a cycle adds no new values
            var key = Nodes.Key(node);
            int bar = key.IndexOf('|', StringComparison.Ordinal), sep = key.IndexOf("::", StringComparison.Ordinal);
            if (bar < 0 || sep < bar || !own.Contains(key[..bar])) return (held, "belongs to code that was not analyzed");
            if (node.StartsWith(Nodes.ArgPrefix, StringComparison.Ordinal) || node.StartsWith(Nodes.ObjectArgPrefix, StringComparison.Ordinal)) {
                bool objects = node.StartsWith(Nodes.ObjectArgPrefix, StringComparison.Ordinal);
                if (!byKey.TryGetValue(key, out var ms)) return (held, "belongs to a method the check did not find");
                // (For an object parameter, a lookup that only handed the method to Harmony.Patch is not a way to call
                // it with any value: what Harmony passes is added below. A Type or member parameter stays any value then.)
                if (CalledFromOutside(ms, objects ? reachOther : reach) is { } why) return (held, $"can be any value: {why}");
                if (untracked.Contains(Nodes.Arg(key, -1))) return (held, "can be any value: the method is used as a delegate");
                if (untracked.Contains(node)) return (held, "is also given a value the check cannot trace");
                // Applied as a patch by hand (R10, policy 43): Harmony also calls the method, and fills each parameter
                // by its name from the original. Known only for the parameters the walker lists (MethodFacts.PatchParameters),
                // of a method without overloads, and only when every original's signature types it: the original's
                // parameter of that name or index, or its result. The value is then of that type or of one derived from it.
                if (objects && manual.TryGetValue(key, out var applied)) {
                    int index = int.TryParse(node[(node.LastIndexOf('#') + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) ? n : -1;
                    if (ms.Count != 1 || !ms[0].PatchParameters.TryGetValue(index, out var parameter))
                        return (held, "can be any value: Harmony calls the method as a patch, and the check does not know what Harmony passes for this parameter");
                    foreach (var p in applied) {
                        var (originals, patchWhy) = PatchedBy(p, visiting, checkWritten);
                        if (originals == null) return (held, $"can be any value: {patchWhy}");
                        foreach (var h in originals) {
                            var sole = h.Value!.Value.Sole!;
                            var of = DeclaredMembers(h.Type, h.Assembly);
                            if (of?.GetValueOrDefault(PatchParameter.TypeKey(sole, parameter)) is not { } declared || MemberTypes.Decode(declared) is not var (type, asm))
                                return (held, $"can be any value: Harmony calls the method as a patch of {h.Type}::{sole}, and the check does not know the type of {PatchParameter.Describe(parameter)} of that method");
                            if (Replaced(parameter, of, sole) is { } replacer)
                                return (held, $"can be any value: Harmony calls the method as a patch of {h.Type}::{sole}, and {replacer} can replace {PatchParameter.Describe(parameter)} of that method through a by-reference parameter");
                            held.Add(new(type, asm, false, Bounded: true));
                        }
                    }
                }
            } else if (node.StartsWith(Nodes.InstancePrefix, StringComparison.Ordinal)) {
                // What Harmony passes as __instance (D7): bounded by the patch target only while Harmony is the only
                // caller this mod has. A patch method is called from outside by design (CalledFromOutside); its own
                // code calling it, taking it as a delegate or reaching it by reflection (to patch another member
                // with it, say) can give it any object.
                if (!byKey.TryGetValue(key, out var ms)) return (held, "belongs to a method the check did not find");
                if (called.Contains(key)) return (held, "can be any object: the mod's own code calls the patch method");
                if (untracked.Contains(Nodes.Arg(key, -1))) return (held, "can be any object: the patch method is used as a delegate");
                if (anyOwnType) return (held, "can be any object: the patch method can be reached by reflection on a type found by a name built at run time");
                // (A lookup that only handed the method to Harmony.Patch is not such a way: what that call patches bounds it, below.)
                if (ms.Any(x => Reached(x.Name, reachOther))) return (held, "can be any object: the patch method can be reached by reflection");
                if (untracked.Contains(node)) return (held, "is also given a value the check cannot trace");
                // (Policy 44) A patch method that takes __instance by reference is given the address of the original's
                // instance argument, and can store any object there for the patch methods called after it.
                if (Replaced(PatchParameter.Instance) is { } replacer) return (held, $"can be any object: {replacer} can replace the instance through a by-reference __instance");
                // Applied by hand (R3): the instance of each original a Harmony.Patch call names with this method. The
                // original must be one method found by a constant name on exactly one type, which that type alone
                // declares (MemberValue.Sole): Harmony then patches that method, which runs on instances of the type
                // or of types derived from it. A type found by name must be the game's alone (as for TypedByName).
                foreach (var p in manual.GetValueOrDefault(key) ?? []) {
                    var (originals, patchWhy) = PatchedBy(p, visiting, checkWritten);
                    if (originals == null) return (held, $"can be any object: {patchWhy}");
                    foreach (var h in originals) held.Add(new(h.Type, h.Assembly, false, Bounded: true));
                }
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
        // (the method can be called from outside, is given one the check does not trace, or is called
        // where no value was recorded). A method nobody calls looks nothing up.
        HashSet<string>? Names(string node, HashSet<string> visiting) {
            var result = new HashSet<string>(StringComparer.Ordinal);
            if (!visiting.Add(node)) return result;  // a cycle adds no new names
            var key = Nodes.Key(node);
            int bar = key.IndexOf('|', StringComparison.Ordinal);
            if (bar < 0 || !own.Contains(key[..bar]) || !byKey.TryGetValue(key, out var ms)) return null;
            if (CalledFromOutside(ms, reach) != null || untracked.Contains(Nodes.Arg(key, -1))) return null;
            // A call the check saw that recorded no string for the parameter: what it passes is not known.
            if (!strings.TryGetValue(node, out var values)) return called.Contains(key) ? null : result;
            foreach (var v in values) {
                if (v.StartsWith('=')) { if (v.Length > 1) result.Add(v[1..]); continue; }  // null names nothing (the lookup throws)
                if (!v.StartsWith('@') || Names(v[1..], visiting) is not { } more) return null;
                result.UnionWith(more);
            }
            return result;
        }
        names = Names;

        // Lookups by a name parameter reach the members every call names, and the types the traced
        // nodes hold are reached by reflection too (see above), by the lookup made on them. Both depend
        // on which methods are reached (a method reached by reflection can be given any name or type),
        // so they are iterated from "nothing reached by them" until nothing changes: the first time a
        // method is reached by reflection at run time, the lookup that found it ran in code reached in
        // another way, so every way in must be inside this loop (H1a-review, F1 guard 1). Reach only
        // grows, so it ends.
        for (bool changed = true; changed;) {
            changed = false;
            foreach (var (pt, pn, pl) in pending.ToList()) changed |= AddReach(pt, Members(null, pn, pl));
            foreach (var m in methods)
                foreach (var r in m.FieldReflection)
                    if (Trace(r.Node, [], false) is { Why: null } t)
                        foreach (var h in t.Held.Where(h => !h.Member)) changed |= Reflected(h.Type, h.Assembly, r.Members, r.NameNode, r.Lookup, h.Bounded);
        }

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
    public void Resolve(List<(MethodFacts Method, string Detail)> unresolved, List<(MethodFacts Method, string Detail, string Type, string? Assembly, bool Member)> bounded, List<(MethodFacts Method, Evidence Evidence)> caps) {
        (HashSet<HeldType> Held, string? Why) Trace(string node, HashSet<string> visiting, bool checkWritten) => trace(node, visiting, checkWritten);
        foreach (var m in methods) {
            foreach (var r in m.FieldReflection) {
                var (held, why) = Trace(r.Node, [], true);
                if (why != null) {
                    // A lookup alone runs nothing; what it finds is checked where it is used.
                    if (r.Invokes) unresolved.Add((m, $"{r.Detail}  ({Nodes.Describe(r.Node)} {why})"));
                    continue;
                }
                // (A member's declared type, HeldType.Value, does not change what reaching it does: one line per member.)
                foreach (var h in held.Select(h => h with { Value = null }).ToHashSet()) {
                    // A type or member known only up to its derived types (or its assembly): bounded
                    // when that is the game's or the mod's code, unresolved otherwise.
                    if (h.Bounded && r.Invokes) {
                        var d = $"{r.Detail}  ({Nodes.Describe(r.Node)} holds {(h.Member ? "a member of " : "")}{Bound(h)})";
                        if (access.Bounded(h.Type, h.Assembly)) bounded.Add((m, d, h.Type, h.Assembly, h.Member));
                        else unresolved.Add((m, d + ", which is not the game's or the mod's code"));
                    }
                    // Silence on purpose for a member: it was accounted for where it was looked up.
                    if (h.Member || h.Type == "*") continue;
                    foreach (var (cap, detail) in access.Reach(h.Type, h.Assembly, Members(r.Members, r.NameNode, r.Lookup), TypeUse.Reflection, frameworkCaps: true, $"{h.Type}  (via {Nodes.Describe(r.Node)})  <-  {m.Name}", derived: h.Bounded))
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
                    if (access.Bounded(h.Type, h.Assembly)) bounded.Add((m, d, h.Type, h.Assembly, h.Member));
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
                        if (access.Bounded(h.Type, h.Assembly)) bounded.Add((m, d, h.Type, h.Assembly, h.Member));
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
