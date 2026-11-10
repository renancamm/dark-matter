// SPDX-License-Identifier: MIT
// Near miss (policy 44): the local holds one of two HarmonyMethods, so the check does not follow either: both patch
// methods count as reached by reflection. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualHandoffLocalTwoHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
    internal static void Other(object __instance) { }
}

public static class ManualHandoffLocalTwo {
    public static void Start(bool flag) {
        var harmony = new Harmony("example.invalid");
        var original = AccessTools.Method(typeof(KSA.Craft), "Update");
        HarmonyMethod postfix;
        if (flag) postfix = new HarmonyMethod(typeof(ManualHandoffLocalTwoHooks), "After");
        else postfix = new HarmonyMethod(typeof(ManualHandoffLocalTwoHooks), "Other");
        harmony.Patch(original, postfix: postfix);
    }
}
