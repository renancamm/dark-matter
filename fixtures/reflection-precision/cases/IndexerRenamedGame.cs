// SPDX-License-Identifier: MIT
// Probe (H7 review): AccessTools.Indexer finds a type's indexer whatever its accessors are called. The game
// stand-in's KSA.Launcher renames its indexer with [IndexerName("Program")] (accessors get_Program, not
// get_Item), and its getter starts what it is given. The check knows game members by name only, so a lookup
// none of whose names the type has reaches every member of it. Expected: Full access, "Starts other
// programs" (before: Limited access, the lookup reached nothing).
using HarmonyLib;

public static class IndexerRenamedEntry {
    public static object Go(KSA.Launcher launcher, string file) => AccessTools.Indexer(typeof(KSA.Launcher)).GetValue(launcher, [file]);
}
