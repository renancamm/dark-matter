// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>Builds the game-API capability map from the game's own assemblies.</summary>
internal static class GameApiProfile {
    /// <summary>
    /// For each game method, public or not (mods can be compiled against publicized game
    /// assemblies), the label capabilities and those that raise the tier (Full access or
    /// Unverified) it reaches through its callees, including path-traced file access, with one
    /// example of each, less what the policy's
    /// <c>game.exempt</c> stops. Findings about the game's own code (reflection the check cannot
    /// trace, unclassified framework members) are not carried: the game's internals are trusted
    /// as a whole, and the map says what its members can do, not how completely the game itself
    /// was read. The game's writes into its own folders (settings, logs, the mod manifest) are left
    /// out: they are the game's own files, written by the game's code, and no mod chooses what the
    /// loader finds there by calling it. A mod's own writes there are labelled.
    /// </summary>
    public static SortedDictionary<string, Reach.Caps> Build(IReadOnlyCollection<AssemblyFacts> game, Policy policy) {
        var methods = game.SelectMany(a => a.Methods).ToList();
        // No type-initializer edges: the game runs its own type initializers as part of its
        // startup whether or not a mod touches the type, so they are not something a call gives a
        // mod. Override edges carry only the capabilities that raise the tier: a virtual game method
        // can dispatch to any game override, which the tier must account for, but labelling every
        // window a mod draws with what every other game window does would bury the labels.
        var reach = Reach.Propagate(methods, Reach.CapabilitySeeds(game, policy, codeWrites: false), Reach.Edges(game, typeInitializers: false),
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
