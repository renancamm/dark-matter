// SPDX-License-Identifier: MIT
// Probe (R10): as ManualParameterGame, with the original found by a helper method of the mod. Expected: Limited
// access with "Uses the game's internals by reflection".
using HarmonyLib;

internal static class ManualParameterNodeHooks {
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterNode {
    static System.Reflection.MethodInfo Find() => AccessTools.Method(typeof(KSA.Dock), "Attach");

    public static void Start() =>
        new Harmony("example.invalid").Patch(Find(), postfix: new HarmonyMethod(typeof(ManualParameterNodeHooks), "After"));
}
