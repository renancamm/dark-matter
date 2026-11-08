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
/// A type named without an assembly is looked up by name in whatever assembly has it: one of the
/// mod's own types is the mod's; otherwise every place that has a type of that name counts, and a
/// name none of them has is code that was not analyzed.
/// </summary>
/// <param name="policy">The policy whose rules classify framework members.</param>
/// <param name="boundary">Resolves the assembly a type lives in.</param>
/// <param name="modAssemblies">Names of the mod's analyzed assemblies (or, for a library profile, the libraries').</param>
/// <param name="modTypes">Types defined in those assemblies.</param>
/// <param name="libraries">Trusted-library profiles.</param>
/// <param name="gameApi">The game-API map.</param>
/// <param name="gameTypes">Types of the game's assemblies, from the game profile; null without one.</param>
internal sealed class TypeAccess(Policy policy, Boundary boundary, IReadOnlySet<string> modAssemblies, IReadOnlySet<string> modTypes,
    TrustedLibraries libraries, IReadOnlyDictionary<string, string[]> gameApi, IReadOnlySet<string>? gameTypes) {

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
    public List<(string Cap, string Detail)> Reach(string type, string? assembly, IReadOnlyList<string>? members, TypeUse use, bool frameworkCaps, string detail) {
        var result = new List<(string, string)>();
        if (assembly == null) {
            // Silence on purpose: the mod's own type of that name is analyzed with the mod.
            if (modTypes.Contains(type)) return result;
            bool found = false;
            if (boundary.IsFrameworkType(type) || policy.TouchesType(type)) { Framework(type, members, frameworkCaps, detail, result); found = true; }
            if (gameTypes?.Contains(type) == true) { Game(type, members, use, detail, result); found = true; }
            foreach (var library in libraries.Defining(type)) { Trusted(library, type, members, use, detail, result); found = true; }
            if (!found) result.Add(("unanalyzed-call", $"{detail}  (a type found by name that is not the mod's, the game's, a trusted library's or one the policy classifies)"));
            return result;
        }
        switch (boundary.Resolve(assembly, modAssemblies)) {
            case AssemblyKind.Mod:
                break;  // the mod's own code, analyzed with it
            case AssemblyKind.Framework:
                Framework(type, members, frameworkCaps, detail, result);
                break;
            case AssemblyKind.Game:
                Game(type, members, use, detail, result);
                break;
            case AssemblyKind.Trusted:
                Trusted(assembly, type, members, use, detail, result);
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
    /// name counts only when no framework type, policy rule or trusted library has that name.
    /// </summary>
    public bool Bounded(string type, string? assembly) {
        if (assembly != null) return boundary.Resolve(assembly, modAssemblies) is AssemblyKind.Mod or AssemblyKind.Game;
        if (type == "*") return false;  // any type of an assembly the check cannot name
        if (modTypes.Contains(type)) return true;
        if (boundary.IsFrameworkType(type) || policy.TouchesType(type) || libraries.Defining(type).Any()) return false;
        return gameTypes?.Contains(type) == true;
    }

    /// <summary>
    /// Whether a member a Harmony transpiler rewrites is the game's code (see Facts.RewriteTarget), the
    /// only code a rewrite stays Unverified for. A type found by name counts only when no mod type,
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
    /// ones (the engine's native and memory code) are not given back (see README, Known gaps). So does
    /// the game-API map's "opens a web address or folder" (shell-open, shell-open-folder): starting a
    /// program, once the instructions can change.
    /// </summary>
    public List<(string Cap, string Detail)> RewriteExempted(string type, string? assembly, IReadOnlyList<string>? members, string detail) {
        var result = new List<(string, string)>();
        bool game = assembly != null ? boundary.Resolve(assembly, modAssemblies) == AssemblyKind.Game : !modTypes.Contains(type) && gameTypes?.Contains(type) == true;
        if (!game) return result;
        foreach (var x in policy.GameExempt) {
            var text = x.Pattern.Text;
            if (!text.Contains("::", StringComparison.Ordinal) && !text.Contains('/', StringComparison.Ordinal)) continue;
            bool hit = members != null
                ? members.Any(m => x.Pattern.Matches(type + "::" + m, null))
                : x.Pattern.Matches(type + "::", null) || text.StartsWith(type + "::", StringComparison.Ordinal) || text.StartsWith(type + "/", StringComparison.Ordinal);
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
                ? members.Any(m => member == prefix + m || (member.StartsWith(type + "/", StringComparison.Ordinal) && member.EndsWith("::" + m, StringComparison.Ordinal)))
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

    void Framework(string type, IReadOnlyList<string>? members, bool caps, string detail, List<(string, string)> result) {
        if (caps) foreach (var cap in policy.CapsOfType(type)) result.Add((cap, detail));
        // Silence on purpose for the type alone: what it can do is decided where its members are reached.
        if (members is { Count: 0 }) return;
        if (!policy.Covers(type, members))
            result.Add(("unclassified-reference", $"{detail}  ({(members == null ? "a member of " + type : type + "::" + string.Join("/", members))} that the policy does not classify)"));
    }

    /// <summary>How a Harmony patch target is reached, from what its patch methods can do.</summary>
    public static TypeUse PatchUse(PatchEffect effect) => effect == PatchEffect.Observes ? TypeUse.Observe : TypeUse.Patch;

    void Game(string type, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result) {
        // Silence on purpose: the game's code runs as it would without the patch.
        if (use == TypeUse.Observe) return;
        var prefix = type + "::";
        // The game runs its own type initializers whether or not a mod touches the type (as in the
        // game profile); a member looked up on a nested type found from this one is that member of
        // any nested type (the walker counts a nested type as the type it was found from).
        var reached = members?.Where(m => m != ".cctor").ToList();
        foreach (var (member, caps) in gameApi) {
            bool hit = reached != null
                ? reached.Any(m => member == prefix + m || (member.StartsWith(type + "/", StringComparison.Ordinal) && member.EndsWith("::" + m, StringComparison.Ordinal)))
                : member.StartsWith(prefix, StringComparison.Ordinal) || member.StartsWith(type + "/", StringComparison.Ordinal);
            if (!hit) continue;
            // A patch sees and can change the target's arguments, so what it can do that raises the
            // tier counts; its labels do not, as for overrides in the game profile.
            foreach (var cap in caps.Where(c => use != TypeUse.Patch || policy.RaisesTier(c)))
                result.Add((cap, $"{detail}  [game API {member}]"));
        }
    }

    void Trusted(string library, string type, IReadOnlyList<string>? members, TypeUse use, string detail, List<(string, string)> result) {
        // Silence on purpose for the type alone: what it can do is decided where its members are reached.
        // Silence on purpose for an observing patch: the library's code runs as it would without it.
        if (members is { Count: 0 } || use == TypeUse.Observe) return;
        var reached = new Reach.Caps();
        bool any = members == null;
        foreach (var m in members ?? [null!]) {
            var caps = m == null ? libraries.LookupType(library, type, out var why) : libraries.Lookup(library, type + "::" + m, out why);
            if (caps == null) {
                // A member no trusted version has does not exist there: the reflection call fails.
                if (m != null && why == TrustedLibraries.NoSuchMember) continue;
                result.Add(("unanalyzed-call", $"{detail}  (trusted library {library}: {why})"));
                return;
            }
            any = true;
            foreach (var (cap, example) in caps) reached.TryAdd(cap, example);
        }
        // None of the members is the type's own: it can be one of a nested type found from it.
        if (!any) {
            if (libraries.LookupType(library, type, out var why) is not { } all) { result.Add(("unanalyzed-call", $"{detail}  (trusted library {library}: {why})")); return; }
            foreach (var (cap, example) in all) reached.TryAdd(cap, example);
        }
        foreach (var (cap, example) in reached.Where(kv => use is not (TypeUse.Patch or TypeUse.Observe) || policy.RaisesTier(kv.Key)))
            result.Add((cap, $"{detail}  [reaches: {example}]"));
    }
}
