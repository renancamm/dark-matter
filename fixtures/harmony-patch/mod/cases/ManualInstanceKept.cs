// SPDX-License-Identifier: MIT
// Near miss (R3): the HarmonyMethod is also kept in a field while it is given to Harmony.Patch, so other code can use
// it to patch another member, or read its method back and call it. The check follows it only while nothing else
// takes it. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualInstanceKeptHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceKept {
    static HarmonyMethod kept;

    public static void Start() =>
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), postfix: kept = new HarmonyMethod(typeof(ManualInstanceKeptHooks), "After"));
}
