// SPDX-License-Identifier: MIT
// Probe (R10, policy 43): a patch applied by hand whose method takes one of the original's parameters by its name,
// declared as object. Harmony passes the original's argument of that name, so the value is a KSA.Craft or a type
// derived from it: the game method Harmony.Patch is given declares "craft" as that. Expected: Limited access with
// "Uses the game's internals by reflection" (before: "Uses reflection the check cannot trace").
using HarmonyLib;

internal static class ManualParameterGameHooks {
    internal static void After(object craft) => craft.GetType().GetMethod("Rename")!.Invoke(craft, ["name"]);
}

public static class ManualParameterGame {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Dock), "Attach"), postfix: new HarmonyMethod(typeof(ManualParameterGameHooks), "After"));
}
