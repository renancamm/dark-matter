// SPDX-License-Identifier: MIT
// Probe (R3, policy 42): a patch applied by hand. The postfix's __instance, declared as object, is the instance of the
// game method Harmony.Patch is given as the original: found by a constant name on a type named by typeof, which
// that type alone declares. The HarmonyMethod is made in the call itself, so nothing else can use it. Expected:
// Limited access with "Uses the game's internals by reflection" (before: "Uses reflection the check cannot trace").
using HarmonyLib;

internal static class ManualInstanceGameHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceGame {
    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), postfix: new HarmonyMethod(typeof(ManualInstanceGameHooks), "After"));
}
