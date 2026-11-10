// SPDX-License-Identifier: MIT
// Probe (R10): as ManualParameterGame, for __result declared as object: the original's result, a KSA.Craft.
// Expected: Limited access with "Uses the game's internals by reflection".
using HarmonyLib;

internal static class ManualParameterResultHooks {
    internal static void After(object __result) => __result.GetType().GetMethod("Rename")!.Invoke(__result, ["name"]);
}

public static class ManualParameterResult {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterResultHooks), "After"));
}
