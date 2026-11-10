// SPDX-License-Identifier: MIT
// Probe (policy 44): a patch applied by hand whose HarmonyMethod waits in a local, across a null test of the original,
// before Harmony.Patch takes it. The local holds nothing else and is loaded only into that call, so nothing else can
// use the HarmonyMethod. Expected: Limited access with "Uses the game's internals by reflection" (before: "Uses
// reflection the check cannot trace").
using HarmonyLib;

internal static class ManualHandoffLocalHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualHandoffLocal {
    public static void Start(bool flag) {
        var harmony = new Harmony("example.invalid");
        var original = AccessTools.Method(typeof(KSA.Craft), "Update");
        var postfix = new HarmonyMethod(typeof(ManualHandoffLocalHooks), "After");
        if (original == null) return;
        harmony.Patch(original, postfix: postfix);
    }
}
