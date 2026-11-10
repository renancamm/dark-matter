// SPDX-License-Identifier: MIT
// Probe (R10): the original is a method of the mod itself, whose parameter "craft" is declared as a game type.
// Expected: no "Uses reflection the check cannot trace"; the lookup is bounded to the game type.
using HarmonyLib;

internal static class ManualParameterOwnHooks {
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterOwn {
    static void Take(KSA.Craft craft) { }

    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(ManualParameterOwn), "Take"), postfix: new HarmonyMethod(typeof(ManualParameterOwnHooks), "After"));
}
