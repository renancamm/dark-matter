// SPDX-License-Identifier: MIT
// Probe (H7b review): the mod's own type has an indexer and derives from the game's KSA.Launcher, whose indexer
// is renamed with [IndexerName("Program")] and starts what it is given. AccessTools.Indexer finds an indexer by
// its parameters whatever it is called, searching the base types: with a string parameter, the game's. The mod
// type's own indexer does not make the lookup its own. Expected: Broad access, "Starts other programs" (policy 25:
// Limited access, "Changes how the game works").
using HarmonyLib;

internal class InheritedIndexerType : KSA.Launcher {
    public int this[int index] => index;
}

public static class InheritedIndexerEntry {
    public static object? Go() => AccessTools.Indexer(typeof(InheritedIndexerType), [typeof(string)]).GetValue(new InheritedIndexerType(), ["example.invalid"]);
}
