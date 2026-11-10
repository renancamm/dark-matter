// SPDX-License-Identifier: MIT
// Near miss (policy 44): the HarmonyMethod in the local is tested for null before the call. The check follows it
// only into Harmony.Patch; any other use, even this harmless one, ends that. Expected: Broad access, "Uses
// reflection the check cannot trace".
using HarmonyLib;

internal static class ManualHandoffLocalTestedHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualHandoffLocalTested {
    public static void Start(bool flag) {
        var harmony = new Harmony("example.invalid");
        var original = AccessTools.Method(typeof(KSA.Craft), "Update");
        var postfix = new HarmonyMethod(typeof(ManualHandoffLocalTestedHooks), "After");
        if (postfix == null) return;
        harmony.Patch(original, postfix: postfix);
    }
}
