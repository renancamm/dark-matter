// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>Builds the game-API capability map from the game's own assemblies.</summary>
internal static class GameApiProfile {
    /// <summary>The one finding a game-API map entry can carry: the member reaches game code that was not read.</summary>
    public const string Unanalyzed = "unanalyzed-call";

    /// <summary>
    /// For each game method, public or not (mods can be compiled against publicized game
    /// assemblies), the label capabilities and those that raise the tier (Full access, any
    /// group) it reaches through its callees, including path-traced file access, with one
    /// example of each, less what the policy's
    /// <c>game.exempt</c> stops. Findings about the game's own code (reflection the check cannot
    /// trace, unclassified framework members) are not carried: the game's internals are trusted
    /// as a whole, and the map says what its members can do, not how completely the game itself
    /// was read. The game's writes into its own folders (settings, logs, the mod manifest) are left
    /// out: they are the game's own files, written by the game's code, and no mod chooses what the
    /// loader finds there by calling it. A mod's own writes there are labelled.
    /// A game method absent from the map was read and reaches nothing the policy counts. What was not
    /// read is never absent: a method whose signature or body cannot be decoded reaches
    /// <see cref="Unanalyzed"/> (so does every game method that can reach it), and an assembly with
    /// native or precompiled code gives every one of its methods that native code, as for a trusted
    /// library (the IL read may not be what runs; the policy's namespace exemptions still apply).
    /// Game members without a body that reach others by name (an UnsafeAccessor) are the game's own
    /// reflection: not carried, as above.
    /// </summary>
    public static SortedDictionary<string, Reach.Caps> Build(IReadOnlyCollection<AssemblyFacts> game, Policy policy) {
        var methods = game.SelectMany(a => a.Methods).ToList();
        var seeds = Reach.CapabilitySeeds(game, policy, codeWrites: false);
        foreach (var a in game) {
            var native = a.Caps.Where(e => e.Cap == "native-code").ToList();
            foreach (var m in a.Methods) {
                var s = Reach.Of(seeds, m.Key);
                foreach (var e in native) s.TryAdd(e.Cap, $"{e.Detail}: {a.Name}");
                if (m.DecodeFailed) s.TryAdd(Unanalyzed, $"{m.Name}: game code the check cannot read");
            }
        }
        // No type-initializer edges: the game runs its own type initializers as part of its
        // startup whether or not a mod touches the type, so they are not something a call gives a
        // mod. Override edges carry only the capabilities that raise the tier: a virtual game method
        // can dispatch to any game override, which the tier must account for, but labelling every
        // window a mod draws with what every other game window does would bury the labels.
        var reach = Reach.Propagate(methods, seeds, Reach.Edges(game, typeInitializers: false),
            policy.RaisesTier,
            (key, cap) => policy.ExemptionFor(null, key[(key.IndexOf('|', StringComparison.Ordinal) + 1)..], cap));
        var profile = new SortedDictionary<string, Reach.Caps>(StringComparer.Ordinal);
        foreach (var m in methods) {
            var caps = reach[m.Key];
            if (caps.Count == 0) continue;  // absent from the map = reaches nothing the policy counts
            var into = profile.TryGetValue(m.Name, out var c) ? c : profile[m.Name] = [];
            foreach (var (cap, d) in caps) into.TryAdd(cap, d);
        }
        return profile;
    }
}
