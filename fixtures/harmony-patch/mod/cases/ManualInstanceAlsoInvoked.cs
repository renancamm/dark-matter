// SPDX-License-Identifier: MIT
// Near miss (R3): the patch is applied by hand as in ManualInstanceGame, but the mod also finds the patch method by
// name and calls it with an object of its choosing. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualInstanceAlsoInvokedHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceAlsoInvoked {
    public static void Start(object anything) {
        new Harmony("example.invalid").Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), postfix: new HarmonyMethod(typeof(ManualInstanceAlsoInvokedHooks), "After"));
        AccessTools.Method(typeof(ManualInstanceAlsoInvokedHooks), "After").Invoke(null, [anything]);
    }
}
