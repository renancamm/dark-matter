// SPDX-License-Identifier: MIT
// Probe (R3, policy 42): as ManualInstanceGame, in the shape most mods write: the original is kept in a local and
// tested for null, the patch method is found with GetMethod and handed straight to a HarmonyMethod with a priority.
// Expected: Limited access with "Uses the game's internals by reflection".
using System.Reflection;
using HarmonyLib;

internal static class ManualInstanceLocalHooks {
    static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceLocal {
    public static void Start() {
        var harmony = new Harmony("example.invalid");
        var original = AccessTools.Method(typeof(KSA.Craft), "Update");
        if (original == null) return;
        harmony.Patch(original, null, new HarmonyMethod(typeof(ManualInstanceLocalHooks).GetMethod("After", BindingFlags.Static | BindingFlags.NonPublic)) { priority = 800 });
    }
}
