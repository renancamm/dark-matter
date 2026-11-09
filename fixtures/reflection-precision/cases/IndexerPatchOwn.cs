// SPDX-License-Identifier: MIT
// Probe (H7 review): a Harmony getter patch without a name on the mod's own type patches its indexer getter,
// renamed here with [IndexerName("Slot")], and the prefix replaces the Type the getter is given, so the
// getter's argument can be any type. Expected: Full access, "Uses reflection the check cannot trace"
// (before: Limited access, the argument was traced to its one direct call's KSA.Tools).
using System;
using HarmonyLib;

internal class Holder {
    [System.Runtime.CompilerServices.IndexerName("Slot")]
    internal string this[Type t] { get { t.GetMethod("CopyName")?.Invoke(null, ["x"]); return ""; } }
    internal static string Direct() => new Holder()[typeof(KSA.Tools)];
}

[HarmonyPatch(typeof(Holder), MethodType.Getter)]
public static class HolderIndexerPatch {
    public static void Prefix(ref Type t) => t = typeof(KSA.UiText);
}

public static class IndexerPatchOwnEntry {
    public static string Go() => Holder.Direct();
}
