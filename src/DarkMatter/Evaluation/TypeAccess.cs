// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>How a type is reached: by reflection, or as the target of a Harmony patch.</summary>
internal enum TypeUse {
    /// <summary>Reflection can run any member it reaches: everything those members can do counts.</summary>
    Reflection,
    /// <summary>A patch wraps the target and sees its arguments: what the target can do that raises the tier counts.</summary>
    Patch,
    /// <summary>
    /// A patch whose patch methods can only observe the target (see <see cref="PatchEffect.Observes"/>):
    /// the target runs as it would without it, so a game or trusted-library target adds nothing.
    /// A framework target is reached as for <see cref="Patch"/>.
    /// </summary>
    Observe,
    /// <summary>A reverse patch or a Harmony delegate runs the target's own code: everything counts.</summary>
    RunsPatch,
}

/// <summary>
/// What reaching a type (or some of its members) can do, by where the type lives. Shared by
/// reflection on a resolved type (the walker's reflected types and Type fields) and Harmony patch
/// targets:
///   the mod itself        nothing more (its code is analyzed)
///   the framework         the type's capabilities by the policy's rules; a member the rules do not
///                         classify is unclassified (as a direct reference to it would be)
///   the game              what the game-API map gives the members reached
///   a trusted library     the members' library profile
///   anything else         code that was not analyzed
/// A type named without an assembly is looked up by name in whatever assembly has it: every place
/// that has a type of that name counts (one of the mod's own types adds nothing, its code is analyzed),
/// and a name none of them has is code that was not analyzed. A mod type does not hide a framework,
/// game or library type of the same name: a lookup by name (AccessTools.TypeByName, Harmony's
/// [HarmonyPatch(string, ...)]) can find either, and the core library's first (G4).
/// </summary>
/// <param name="policy">The policy whose rules classify framework members.</param>
/// <param name="boundary">Resolves the assembly a type lives in.</param>
/// <param name="modAssemblies">Names of the mod's analyzed assemblies (or, for a library profile, the libraries').</param>
/// <param name="modTypes">Types defined in those assemblies.</param>
/// <param name="libraries">Trusted-library profiles.</param>
/// <param name="gameApi">The game-API map.</param>
/// <param name="gameTypes">Types of the game's assemblies, from the game profile; null without one.</param>
/// <param name="analyzed">The analyzed assemblies, for the base types of their types and the names of their
/// members (H7b: a lookup on one of them also finds what it inherits); null for none.</param>
internal sealed class TypeAccess(Policy policy, Boundary boundary, IReadOnlySet<string> modAssemblies, IReadOnlySet<string> modTypes,
    TrustedLibraries libraries, IReadOnlyDictionary<string, string[]> gameApi, IReadOnlySet<string>? gameTypes,
    IReadOnlyCollection<AssemblyFacts>? analyzed = null) {

    // Each analyzed type's base type, with the assembly it lives in.
    readonly Dictionary<string, (string Type, string Assembly)> ownBases = OwnBaseTypes(analyzed);
    // The simple names of each analyzed type's methods, fields, properties and events.
    readonly Dictionary<string, HashSet<string>> ownNames = OwnMemberNames(analyzed);
    // The analyzed types nested in each type, at any depth.
    readonly Lazy<Dictionary<string, List<string>>> ownNested = new(() => NestedTypes(modTypes));

    static Dictionary<string, List<string>> NestedTypes(IReadOnlySet<string> types) {
        var nested = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var t in types.Order(StringComparer.Ordinal))
            for (int i = t.IndexOf('/'); i > 0; i = t.IndexOf('/', i + 1)) {
                if (!nested.TryGetValue(t[..i], out var list)) nested[t[..i]] = list = [];
                list.Add(t);
            }
        return nested;
    }

    static Dictionary<string, (string, string)> OwnBaseTypes(IReadOnlyCollection<AssemblyFacts>? analyzed) {
        var bases = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
        foreach (var a in analyzed ?? [])
            foreach (var (t, b) in a.BaseTypes)
                // Two analyzed types of one name: a lookup by that name can find either, and the first
                // recorded is followed. The other's own members are analyzed with it; what it inherits is
                // followed only when its base is the same (by name, a type found by name is any of them).
                bases.TryAdd(t, (b, a.BaseTypeAssemblies.GetValueOrDefault(t, "")));
        return bases;
    }

    static Dictionary<string, HashSet<string>> OwnMemberNames(IReadOnlyCollection<AssemblyFacts>? analyzed) {
        var names = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        void Add(string member) {
            int sep = member.LastIndexOf("::", StringComparison.Ordinal);
            if (sep <= 0) return;
            if (!names.TryGetValue(member[..sep], out var set)) names[member[..sep]] = set = new(StringComparer.Ordinal);
            set.Add(member[(sep + 2)..]);
        }
        foreach (var a in analyzed ?? []) {
            foreach (var m in a.Methods) Add(m.Name);
            foreach (var f in a.Fields) Add(f);
            foreach (var of in a.Accessors.Values) foreach (var o in of) Add(o);
        }
        return names;
    }

    /// <summary>
    /// Capabilities and findings (<see cref="Policy.Findings"/>) reached through <paramref name="type"/>.
    /// File capabilities come as they are; callers count them as outside the game (the path is not traceable).
    /// </summary>
    /// <param name="type">"Namespace.Type", nested types as "Outer/Inner".</param>
    /// <param name="assembly">Where the type lives; null to look it up by name, "" when it cannot be determined.</param>
    /// <param name="members">The members reached, or null for any member. Empty: the type itself,
    /// no member, which only matters when the type lives in code that was not analyzed.</param>
    /// <param name="use">Reflection or a patch (see <see cref="TypeUse"/>).</param>
    /// <param name="frameworkCaps">Also add a framework type's capabilities by the policy's rules (the
    /// walker adds them itself where it resolves a type, so it passes false).</param>
    /// <param name="detail">Evidence text.</param>
    /// <param name="nullTestOnly">The type is found by name only to test whether it exists (see
    /// <see cref="ReflectedType.NullTestOnly"/>): a name nothing has adds nothing, it finds no type (H9).</param>
    /// <param name="derived">The type is known only up to its derived types (the run-time type of a value of that
    /// declared type, see <see cref="ReflectedType.Derived"/>): for a game type, the same members of every game type
    /// deriving from it are reached too (D9; see <see cref="GameDerived"/>).</param>
    public List<(string Cap, string Detail)> Reach(string type, string? assembly, IReadOnlyList<string>? members, TypeUse use, bool frameworkCaps, string detail, bool nullTestOnly = false,
        bool derived = false) {
        var result = ReachExactly(type, assembly, members, use, frameworkCaps, detail, nullTestOnly);
        if (derived && use != TypeUse.Observe && (assembly != null ? boundary.Resolve(assembly, modAssemblies) == AssemblyKind.Game : gameTypes?.Contains(type) == true))
            GameDerived(type, members, use, detail, result);
        return result;
    }

    List<(string Cap, string Detail)> ReachExactly(string type, string? assembly, IReadOnlyList<string>? members, TypeUse use, bool frameworkCaps, string detail, bool nullTestOnly) {
        var result = new List<(string, string)>();
        if (assembly == null) {
            // Silence on purpose for the mod's own type of that name: it is analyzed with the mod. What it
            // inherits from outside the mod is not (see Inherited).
            bool found = modTypes.Contains(type);
            if (found) Inherited(type, members, use, detail, result);
            if (boundary.IsFrameworkType(type) || policy.TouchesType(type)) { Framework(type, members, frameworkCaps, detail, result); found = true; }
            if (gameTypes?.Contains(type) == true) { Game(type, members, use, detail, result); found = true; }
            foreach (var library in libraries.Defining(type)) { Trusted(library, type, members, use, detail, result); found = true; }
            if (!found && !(nullTestOnly && members is { Count: 0 })) result.Add(("unanalyzed-call", $"{detail}  (a type found by name that is not the mod's, the game's, a trusted library's or one the policy classifies)"));
            return result;
        }
        switch (boundary.Resolve(assembly, modAssemblies)) {
            case AssemblyKind.Mod:
                // The mod's own code is analyzed with it; what the type inherits from outside the mod is not.
                Inherited(type, members, use, detail, result);
                break;
            case AssemblyKind.Framework:
                Framework(type, members, frameworkCaps, detail, result);
                break;
            case AssemblyKind.Game:
                Game(type, members, use, detail, result);
                break;
            case AssemblyKind.Trusted:
                Trusted(assembly, type, members, use, detail, result);
                break;
            // Named like a game assembly that this game build does not have (H9).
            case AssemblyKind.Unanalyzed when boundary.MissingGameAssembly(assembly):
                result.Add(("missing-game-code", $"{detail}  (in {assembly}, an assembly named like the game's that this game build does not have, which was not analyzed)"));
                break;
            default:
                result.Add(("unanalyzed-call", $"{detail}  (in {(assembly.Length > 0 ? assembly : "an assembly the check cannot determine")}, which was not analyzed)"));
                break;
        }
        return result;
    }

    /// <summary>
    /// Whether reflection known only up to <paramref name="type"/> and its derived types ("*": any type
    /// of <paramref name="assembly"/>) stays within the game's or the mod's own code. A type found by
    /// name counts only when no framework type, policy rule or trusted library has that name (whether or
    /// not the mod has a type of that name, G4).
    /// </summary>
    public bool Bounded(string type, string? assembly) {
        if (assembly != null) return boundary.Resolve(assembly, modAssemblies) is AssemblyKind.Mod or AssemblyKind.Game;
        if (type == "*") return false;  // any type of an assembly the check cannot name
        if (boundary.IsFrameworkType(type) || policy.TouchesType(type) || libraries.Defining(type).Any()) return false;
        return modTypes.Contains(type) || gameTypes?.Contains(type) == true;
    }

    /// <summary>
    /// Whether a member a Harmony transpiler rewrites is the game's code (see Facts.RewriteTarget), the
    /// only code a rewrite stays deep game access for. A type found by name counts only when no mod type,
    /// framework type, policy rule or trusted library has that name; a type known only up to its derived
    /// types counts only as any type of a game assembly ("*"), since a derived type can be the mod's or
    /// another assembly's. The mod's own code does not count: the analysis of its IL (including the
    /// narrowings proved on it, such as a folder it opens) holds only as written.
    /// </summary>
    public bool IsGame(string type, string? assembly, bool derived) {
        if (assembly != null) return boundary.Resolve(assembly, modAssemblies) == AssemblyKind.Game && (!derived || type == "*");
        if (derived || type == "*" || modTypes.Contains(type)) return false;
        if (boundary.IsFrameworkType(type) || policy.TouchesType(type) || libraries.Defining(type).Any()) return false;
        return gameTypes?.Contains(type) == true;
    }

    /// <summary>
    /// For a mod that rewrites game code (a Harmony transpiler): the capabilities a game exemption that
    /// names a type or member stops on <paramref name="type"/>'s members (<paramref name="members"/>, null
    /// for any), with evidence. Those exemptions assume the game's own code runs there; namespace-wide
    /// ones (the engine's native and memory code) are not given back (see docs/known-gaps.md). So does
    /// the game-API map's "opens a web address or folder" (shell-open, shell-open-folder): starting a
    /// program, once the instructions can change.
    /// </summary>
    public List<(string Cap, string Detail)> RewriteExempted(string type, string? assembly, IReadOnlyList<string>? members, string detail) {
        var result = new List<(string, string)>();
        // Found by name, the game's type of that name counts even when the mod has one too (G4, see Reach).
        bool game = assembly != null ? boundary.Resolve(assembly, modAssemblies) == AssemblyKind.Game : gameTypes?.Contains(type) == true;
        if (!game) return result;
        foreach (var x in policy.GameExempt) {
            var text = x.Pattern.Text;
            if (!text.Contains("::", StringComparison.Ordinal) && !text.Contains('/', StringComparison.Ordinal)) continue;
            bool Whole(string t) => x.Pattern.Matches(t + "::", null) || text.StartsWith(t + "::", StringComparison.Ordinal) || text.StartsWith(t + "/", StringComparison.Ordinal);
            // A reached name matches ignoring case, or as a prefix (ReflectionApis.MemberMatches): an
            // exemption on a member or a nested type of that type that the name can find counts too.
            bool Member(string m) => x.Pattern.Matches(type + "::" + m, null)
                || (text.StartsWith(type + "::", StringComparison.Ordinal) && ReflectionApis.MemberMatches(m, text[(type.Length + 2)..]));
            // A nested type: the exemption on it by its name as written (Whole), on every nested type of
            // the type ("T/", which names none: H3 review), or on one whose name the lookup can find.
            bool Nested(string m) => Whole(type + m) || x.Pattern.Matches(type + "::", null) || x.Pattern.Matches(type + "/", null)
                || (text.StartsWith(type + "/", StringComparison.Ordinal) && text.IndexOfAny(['/', ':'], type.Length + 1) is int end
                    && ReflectionApis.MemberMatches(m[ReflectionApis.NestedPrefix.Length..], end < 0 ? text[(type.Length + 1)..] : text[(type.Length + 1)..end]));
            bool hit = members != null
                ? members.Any(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal) ? Nested(m) : Member(m))
                : Whole(type);
            if (!hit) continue;
            foreach (var cap in x.Caps)
                result.Add((cap, $"{detail}  (a transpiler can change this game code, which the policy exempts from {cap} as its own: {x.Reason})"));
        }
        // Likewise what the game-API map records as opening a fixed web address or a folder the game
        // method has just created: proved on the game's instructions as written, and starting a program
        // once a transpiler can change what is opened.
        var prefix = type + "::";
        foreach (var (member, caps) in gameApi) {
            if (!caps.Any(c => c is "shell-open" or "shell-open-folder")) continue;
            bool hit = members != null
                ? members.Any(m => Names(type, m, member))
                : member.StartsWith(prefix, StringComparison.Ordinal) || member.StartsWith(type + "/", StringComparison.Ordinal);
            if (hit) result.Add(("process-start", $"{detail}  [game API {member}]  (opens a web address or folder that a transpiler can change into a program to start)"));
        }
        return result;
    }

    /// <summary>Whether a type is one of the analyzed code's own (by its assembly, or by name when that is not given).</summary>
    public bool IsOwn(string type, string? assembly) =>
        assembly != null ? boundary.Resolve(assembly, modAssemblies) == AssemblyKind.Mod : modTypes.Contains(type);

    /// <summary>Whether an assembly is one of the analyzed code's own.</summary>
    public bool IsOwnAssembly(string assembly) => boundary.Resolve(assembly, modAssemblies) == AssemblyKind.Mod;

    // The runtime's root types: every member is classified safe, or reflection (Object.GetType), by the policy.
    static readonly HashSet<string> RootTypes = ["System.Object", "System.ValueType", "System.Enum"];

    /// <summary>
    /// What a lookup on one of the analyzed code's own types reaches through the types it inherits from outside
    /// that code (H7b). GetMethod, GetMembers, AccessTools.Method and a Harmony target named through the type find
    /// inherited members too (Harmony's attribute targets look at the declared members only in some versions;
    /// the check counts the inherited ones either way). The base types are followed while they are the analyzed
    /// code's own; the first one that is not is reached with the same members as if it had been looked up
    /// itself: a game type through the game-API map along its game base types (as <see cref="Game"/>), a
    /// trusted library's type by its library profile (members of types outside the trusted file fail closed),
    /// a framework type by the policy's rules for the names it has (the root types add nothing), anything else
    /// is code that was not analyzed. A property or event name one of the analyzed types in the chain has is
    /// that type's own: it does not make every inherited member reached (see <see cref="Game"/>); an indexer's
    /// is not (H7b review: AccessTools.Indexer finds one by its parameters). The analyzed types nested in the
    /// type are followed too (H7b review). Interfaces are not followed: a lookup on a class does not return its
    /// interfaces' members.
    /// </summary>
    void Inherited(string type, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result) {
        // Silence on purpose for the type alone: what it can do is decided where its members are reached.
        if (members is { Count: 0 }) return;
        // The walker counts a nested type found from a type as that type (GetNestedType, AccessTools.Inner, which
        // searches the base types), and a lookup on a nested type finds what it inherits: each analyzed type
        // nested in a type of the chain is followed too, with the names the lookup reaches on it (H7b review,
        // see NestedReached), as a trusted library's FindMatching and Game do. For a nested type, only those of
        // its base types (its own nested types were enumerated with the type it is nested in, at any depth).
        var family = new List<(string Type, IReadOnlyList<string>? Members, List<string> Chain, (string Type, string Assembly)? Outside)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(string t, IReadOnlyList<string>? m) {
            if (family.Count < 256 && seen.Add(t + "|" + MembersKey(m)) && OwnChain(t, out var outside) is { } chain) family.Add((t, m, chain, outside));
        }
        Add(type, members);
        for (int i = 0; i < family.Count; i++)
            foreach (var c in family[i].Chain.Skip(i == 0 ? 0 : 1))
                foreach (var n in OwnNested(c)) {
                    var rn = NestedReached(c, n, family[i].Members);
                    if (rn is not { Count: 0 }) Add(n, rn);
                }
        // A name one of these analyzed types (or their analyzed base types) has is that code's own member (see
        // Game and Trusted). Not an indexer's: AccessTools.Indexer finds an indexer by its parameters, whatever
        // it is called, so a base type's renamed indexer can be the one found although the type has its own
        // (recorded as get_Item/set_Item, see ReflectionApis.MemberNames).
        bool Own(string n) => !IsIndexerName(n)
            && family.Any(f => f.Chain.Any(c => ownNames.TryGetValue(c, out var names) && names.Any(x => ReflectionApis.MemberMatches(n, x))));
        foreach (var (t, m, _, outside) in family)
            if (outside is { } b) InheritedFrom(t, b, m, use, detail, result, Own);
    }

    static bool IsIndexerName(string n) =>
        AccessorPrefixes.FirstOrDefault(p => n.Length > p.Length && n.StartsWith(p, StringComparison.OrdinalIgnoreCase)) is { } p
            ? n[p.Length..].Equals("Item", StringComparison.OrdinalIgnoreCase) : n.Equals("Item", StringComparison.OrdinalIgnoreCase);

    // An analyzed type with its base types while they are analyzed types of the mod (the type first), and the
    // first base type that is not (null when there is none); null for a cycle, which is not a real hierarchy.
    List<string>? OwnChain(string type, out (string Type, string Assembly)? outside) {
        outside = null;
        var chain = new List<string> { type };
        for (var t = type; ownBases.TryGetValue(t, out var b); t = b.Type) {
            if (chain.Contains(b.Type) || chain.Count > 64) return null;
            if (boundary.Resolve(b.Assembly, modAssemblies) == AssemblyKind.Mod && modTypes.Contains(b.Type)) { chain.Add(b.Type); continue; }
            outside = b;
            break;
        }
        return chain;
    }

    // The analyzed types nested in type, at any depth.
    List<string> OwnNested(string type) => ownNested.Value.TryGetValue(type, out var nested) ? nested : [];

    // What a lookup on the analyzed type reaches through b, the first of its base types outside the analyzed code.
    void InheritedFrom(string type, (string Type, string Assembly) b, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result, Func<string, bool> own) {
        var d = $"{detail}  (inherited by {type} from {b.Type})";
        switch (boundary.Resolve(b.Assembly, modAssemblies)) {
            case AssemblyKind.Framework:
                // Silence on purpose for the root types (see RootTypes).
                if (RootTypes.Contains(b.Type)) return;
                // A name the framework type (with its base types) does not have finds nothing there
                // (names compare ignoring case, a name ending in '*' is a prefix, as in Game).
                var rest = members?.Where(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal) || m.EndsWith('*')
                    || boundary.FrameworkDeclaring(b.Type, m, ignoreCase: true) != null).ToList();
                if (rest is { Count: 0 }) return;
                Framework(b.Type, rest, true, d, result);
                return;
            case AssemblyKind.Game:
                Game(b.Type, members, use, d, result, own);
                return;
            case AssemblyKind.Trusted:
                Trusted(b.Assembly, b.Type, members, use, d, result, own);
                return;
            default:
                result.Add(("unanalyzed-call", $"{d}  ({(b.Assembly.Length > 0 ? b.Assembly : "an assembly the check cannot determine")}, which was not analyzed)"));
                return;
        }
    }

    void Framework(string type, IReadOnlyList<string>? members, bool caps, string detail, List<(string, string)> result) {
        // A nested type a GetMember name finds (when the framework has one of that name): any member of it.
        // (Ignoring case, and a name ending in '*' as a prefix: ReflectionApis.MemberMatches.)
        if (members != null && members.Any(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal))) {
            var nested = members.Where(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal)).ToList();
            foreach (var n in boundary.FrameworkNestedTypes(type).Where(t => nested.Any(m => ReflectionApis.ReachesNested(type, m, t))))
                Framework(n, null, true, detail, result);
            members = [.. members.Where(m => !m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal))];
        }
        if (caps) foreach (var cap in policy.CapsOfType(type)) result.Add((cap, detail));
        // Silence on purpose for the type alone: what it can do is decided where its members are reached.
        if (members is { Count: 0 }) return;
        if (!policy.Covers(type, members))
            result.Add(("unclassified-reference", $"{detail}  ({(members == null ? "a member of " + type : type + "::" + string.Join("/", members))} that the policy does not classify)"));
    }

    // Whether a reached member name (see ReflectionApis.MemberNames) of a type is a game-API map entry:
    // that member, one of that name of a nested type (the walker counts a nested type as the type it was
    // found from), or, for "/Name", any member of the nested type Name; ignoring case, and a name ending
    // in '*' as a prefix (ReflectionApis.MemberMatches, H3).
    static bool Names(string type, string reached, string member) => ReflectionApis.ReachesMember(type, reached, member);

    /// <summary>How a Harmony patch target is reached, from what its patch methods can do.</summary>
    public static TypeUse PatchUse(PatchEffect effect) => effect == PatchEffect.Observes ? TypeUse.Observe : TypeUse.Patch;

    // The names a lookup on outer (members, as for Reach) reaches on nested, a type nested in it at any depth
    // ("outer/A/B"): the walker counts a nested type found from a type as that type, so each name is one of the
    // nested type too, and "/Name" reaches every member of a nested type Name and of the types nested in it
    // (any segment of the path counts: a nested type found from a nested one is counted as the outer type too).
    // Null: every member.
    static List<string>? NestedReached(string outer, string nested, IReadOnlyList<string>? members) {
        if (members == null) return null;
        var segments = nested[(outer.Length + 1)..].Split('/');
        if (members.Any(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal)
            && segments.Any(s => ReflectionApis.MemberMatches(m[ReflectionApis.NestedPrefix.Length..], s)))) return null;
        return [.. members.Where(m => !m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal))];
    }

    static string MembersKey(IReadOnlyList<string>? members) => members == null ? "*" : string.Join("\n", members);

    // own: for a game type a type of the analyzed code inherits from (see Inherited), whether that code's types
    // have a member of a reached name.
    /// <summary>
    /// What a lookup on a game type known only up to its derived types reaches besides that type (D9): the same
    /// members of each game type deriving from it, directly or through other game types, by base type or by
    /// interface (<see cref="Boundary.GameDerived"/>). Only what such a type adds: the members it shares with the
    /// declared type (that type's chain, and the framework type past it) were reached with it. The mod's own derived
    /// types are analyzed with the mod (and their methods count as reached, see FieldProvenance); a trusted library's
    /// or another mod's type deriving from a game type is not followed (docs/known-gaps.md).
    /// </summary>
    void GameDerived(string type, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result) {
        var covered = boundary.GameChain(type, out _).ToHashSet(StringComparer.Ordinal);
        covered.Add(type);
        var reached = members?.Where(m => m != ".cctor").ToList();
        foreach (var d in boundary.GameDerived(type))
            GameOne(d, reached, use, $"{detail}  (as {d}, a game type derived from {type})", result, null, false, out _, covered);
    }

    void Game(string type, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result, Func<string, bool>? own = null) {
        // Silence on purpose: the game's code runs as it would without the patch.
        if (use == TypeUse.Observe) return;
        // The game runs its own type initializers whether or not a mod touches the type (as in the
        // game profile); a member looked up on a nested type found from this one is that member of
        // any nested type (the walker counts a nested type as the type it was found from).
        var reached = members?.Where(m => m != ".cctor").ToList();
        // That nested type is searched with its own base types too (H7b review, as a trusted library's
        // FindMatching does): each game type nested in a type of the chain whose base type is not one of the
        // root types is reached through what it inherits, with the names the lookup reaches on it (see
        // NestedReached). A property name the outer lookup knows (see GameOne) is known there too.
        var todo = new Queue<(string Type, List<string>? Reached, string Detail)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        Func<string, bool>? known = own;
        bool first = true;
        for (var item = (type, reached, detail); ;) {
            var chain = GameOne(item.type, item.reached, use, item.detail, result, known, !first, out var itemKnown);
            // Nested types of the type itself were enumerated where it was found (any depth), so for a nested
            // one only those of its base types.
            var searched = chain.Skip(first ? 0 : 1).ToList();
            if (first) { known = itemKnown; first = false; }
            foreach (var c in searched)
                foreach (var n in boundary.GameNestedWithBase(c)) {
                    if (RootTypes.Contains(boundary.GameBases![n])) continue;
                    var rn = NestedReached(c, n, item.reached);
                    if (rn is { Count: 0 } || seen.Count >= 256 || !seen.Add(n + "|" + MembersKey(rn))) continue;
                    todo.Enqueue((n, rn, $"{detail}  (nested type {n} of {c}, inheriting from {boundary.GameBases[n]})"));
                }
            if (!todo.TryDequeue(out var next)) return;
            item = (next.Type, next.Reached, next.Detail);
        }
    }

    // inherited: for a nested type reached through the type it was found from (see Game), only what it inherits
    // (its own members were reached with that type). known: the Known used here, for the nested types.
    // covered: for a derived type (see GameDerived), the types whose members were already reached: they, and the
    // framework type past them, are not reached again.
    List<string> GameOne(string type, List<string>? reached, TypeUse use, string detail, List<(string, string)> result, Func<string, bool>? own, bool inherited,
        out Func<string, bool>? known, HashSet<string>? covered = null) {
        known = own;
        // A lookup by name searches the base types too (GetMethod, GetMembers, AccessTools.Method): the
        // members of each game base type count, and past the last one, those of the framework type it
        // derives from, by the policy's rules (a name the game types have is theirs). Without a game
        // profile, or for a type it does not have, the type alone.
        var chain = boundary.GameChain(type, out var beyond);
        bool profiled = chain.Count > 0;
        if (chain.Count == 0) chain.Add(type);
        bool framework = beyond != null && boundary.IsFrameworkType(beyond);
        // A property, event or indexer looked up by its name: the lookup finds its accessors by the
        // metadata, whatever they are called, while the game-API map knows methods by name and
        // ReflectionApis.MemberNames assumes C#'s names (get_P, set_P; get_Item for an indexer). An indexer
        // renamed with [IndexerName], an explicit interface implementation (I.get_P) or hand-written IL has
        // others. When the type (with its game base types, the framework type past them, and the types
        // nested in them, which the walker counts as the type they were found from) has no member of the
        // name or of an accessor name, the accessors are some other members of those types (an accessor
        // is a method of the type that declares the property): every member of them is reached. Without the
        // profile's member names, so is every member for an indexer lookup (H7 review).
        string? unnamed = null;
        if (reached != null && profiled && (beyond == null || framework)) {
            Func<string, bool> Known = n => own?.Invoke(n) == true || chain.Any(t => boundary.GameMembersWithNested(t).Any(x => ReflectionApis.MemberMatches(n, x)))
                || (framework && (n.EndsWith('*') || boundary.FrameworkDeclaring(beyond!, n, ignoreCase: true) != null));
            known = Known;
            unnamed = AccessorLookups(reached).FirstOrDefault(l => !l.Candidates.Any(Known)).Name;
        } else if (reached != null && !profiled) {
            unnamed = reached.FirstOrDefault(m => (m.Equals("get_Item", StringComparison.OrdinalIgnoreCase) || m.Equals("set_Item", StringComparison.OrdinalIgnoreCase))
                && own?.Invoke("Item") != true) is { } indexer ? indexer[4..] : null;
        }
        var why = unnamed == null ? "" : $"  (a property, event or indexer looked up as {unnamed}: no member of {type} has that name or an accessor's, so every member counts)";
        foreach (var t in chain.Skip(inherited ? 1 : 0)) {
            if (covered?.Contains(t) == true) continue;
            var prefix = t + "::";
            foreach (var (member, caps) in gameApi) {
                bool hit = reached != null && unnamed == null
                    ? reached.Any(m => Names(t, m, member))
                    : member.StartsWith(prefix, StringComparison.Ordinal) || member.StartsWith(t + "/", StringComparison.Ordinal);
                if (!hit) continue;
                // A patch sees and can change the target's arguments, so what it can do that raises the
                // tier counts (the game's XML for a type its caller chooses included: a prefix can change the
                // Type it is given); its labels do not, as for overrides in the game profile.
                foreach (var cap in caps.Where(c => use != TypeUse.Patch || policy.RaisesTier(c)))
                    result.Add((cap, $"{detail}  [game API {member}]{why}"));
            }
        }
        if (beyond == null || (covered != null && chain.Any(covered.Contains))) return chain;
        // A name no game type of the chain has is one the framework type has (or a prefix), or none: then
        // the lookup finds nothing (names compare ignoring case, as in ReflectionApis.MemberMatches).
        var rest = reached?.Where(m => !m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal)
            && !chain.Any(t => boundary.GameMembersOf(t).Any(n => ReflectionApis.MemberMatches(m, n)))
            && (!framework || m.EndsWith('*') || boundary.FrameworkDeclaring(beyond, m, ignoreCase: true) != null)).ToList();
        // Silence on purpose: every name reached is a game member (or a nested type), found above, or none.
        if (rest is { Count: 0 }) return chain;
        if (framework) Framework(beyond, rest, true, $"{detail}  (inherited from {beyond})", result);
        else result.Add(("unanalyzed-call", $"{detail}  ({chain[^1]} derives from {beyond}, which is neither the game's nor the framework's)"));
        return chain;
    }

    // How ReflectionApis.MemberNames names the accessors of a property, event or indexer a lookup finds by its name.
    static readonly string[] AccessorPrefixes = ["get_", "set_", "add_", "remove_", "raise_"];

    // The properties, events and indexers a lookup reaches by C#'s accessor names (GetProperty("P") as get_P
    // and set_P, AccessTools.Indexer as get_Item, a Harmony getter target as get_P), each with the names that
    // show the type has it: the name itself (a method or field GetMember finds) and every accessor name.
    static IEnumerable<(string Name, string[] Candidates)> AccessorLookups(IEnumerable<string> reached) =>
        reached.Where(m => !m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal))
            .Select(m => AccessorPrefixes.FirstOrDefault(p => m.Length > p.Length && m.StartsWith(p, StringComparison.OrdinalIgnoreCase)) is { } p ? m[p.Length..] : null)
            .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(b => (b, (string[])[b, .. AccessorPrefixes.Select(p => p + b)]));

    // own: as for Game.
    void Trusted(string library, string type, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result, Func<string, bool>? own = null) {
        // Silence on purpose for the type alone: what it can do is decided where its members are reached.
        // Silence on purpose for an observing patch: the library's code runs as it would without it.
        if (members is { Count: 0 } || use == TypeUse.Observe) return;
        // For a type of the analyzed code deriving from this one: a name only that code has is its own member
        // (analyzed with it), not one of a nested type found from this one (which reaches every member below).
        if (own != null && members != null) {
            members = [.. members.Where(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal) || !own(m)
                || libraries.LookupMatching(library, type, m, out var w, out _) != null || w is not (TrustedLibraries.NoSuchMember or TrustedLibraries.NoSuchType))];
            if (members.Count == 0) return;
        }
        var reached = new Reach.Caps();
        bool any = members == null;
        // A reached name matches ignoring case, and one ending in '*' as a prefix (ReflectionApis.MemberMatches).
        var atCallMembers = new List<string>();  // the names reached and the members they find, for "atCall" below
        foreach (var m in members ?? [null!]) {
            // "/Name": every member of each nested type of that name (see ReflectionApis.MemberNames).
            bool nested = m != null && m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal);
            if (nested && !libraries.Profiled(library)) {
                libraries.LookupType(library, type + m, out var unprofiled);
                result.Add(("unanalyzed-call", $"{detail}  (trusted library {library}: {unprofiled})"));
                return;
            }
            if (nested) {
                foreach (var n in libraries.NestedTypes(library, type).Where(t => ReflectionApis.ReachesNested(type, m!, t))) {
                    var nestedCaps = libraries.LookupType(library, n, out var nestedWhy);
                    if (nestedCaps == null) {
                        if (nestedWhy == TrustedLibraries.NoSuchType) continue;
                        result.Add(("unanalyzed-call", $"{detail}  (trusted library {library}: {nestedWhy})"));
                        return;
                    }
                    any = true;
                    atCallMembers.Add(ReflectionApis.NestedPrefix + n[(type.Length + 1)..]);
                    foreach (var (cap, example) in nestedCaps) reached.TryAdd(cap, example);
                }
                continue;
            }
            List<string>? found = null;
            var caps = m == null ? libraries.LookupType(library, type, out var why) : libraries.LookupMatching(library, type, m, out why, out found);
            if (caps == null) {
                // A member (or nested type) no trusted version has does not exist there: the reflection call fails.
                if (m != null && why is TrustedLibraries.NoSuchMember or TrustedLibraries.NoSuchType) continue;
                result.Add(("unanalyzed-call", $"{detail}  (trusted library {library}: {why})"));
                return;
            }
            any = true;
            if (m != null) { atCallMembers.AddRange(found ?? []); atCallMembers.Add(m); }
            foreach (var (cap, example) in caps) reached.TryAdd(cap, example);
        }
        // None of the members is the type's own: it can be one of a nested type found from it. Or a property,
        // event or indexer is looked up by a name that neither it nor any accessor name of it has: its
        // accessors have other names (see Game), and every member counts.
        if (any && members != null && AccessorLookups(members).Any(l => !l.Candidates.Any(c => own?.Invoke(c) == true || libraries.LookupMatching(library, type, c, out _, out _) != null)))
            any = false;
        if (!any) {
            if (libraries.LookupType(library, type, out var why) is not { } all) { result.Add(("unanalyzed-call", $"{detail}  (trusted library {library}: {why})")); return; }
            foreach (var (cap, example) in all) reached.TryAdd(cap, example);
        }
        foreach (var (cap, example) in reached.Where(kv => use is not (TypeUse.Patch or TypeUse.Observe) || policy.RaisesTier(kv.Key)))
            result.Add((cap, $"{detail}  [reaches: {example}]"));
        // A member whose exemption holds only for the mod's direct call (the policy's "atCall": the
        // arguments it is given are traced there) is run here with arguments the check does not see:
        // by reflection, or patched (a prefix can change them).
        var atCall = members == null || !any
            ? (policy.CheckedAtCallInType(library, type) ? type + "::" : null)
            : atCallMembers.Select(m => m.StartsWith(ReflectionApis.NestedPrefix, StringComparison.Ordinal) ? (policy.CheckedAtCallInType(library, type + m) ? type + m + "::" : null)
                : policy.CheckedAtCall(library, type + "::" + m) ? type + "::" + m : null).FirstOrDefault(m => m != null);
        if (atCall != null)
            result.Add(("unresolved-reflection", $"{detail}  (trusted library {library}: {atCall}{(atCall.EndsWith("::", StringComparison.Ordinal) ? "*" : "")} traces its arguments only at a direct call from the mod)"));
    }
}
