// SPDX-License-Identifier: MIT
// Near miss (policy 44): the address of the local holding the HarmonyMethod is taken, so it can be read or replaced
// where the check does not look. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualHandoffLocalRefHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualHandoffLocalRef {
    static void Look(ref HarmonyMethod what) { }

    public static void Start(bool flag) {
        var harmony = new Harmony("example.invalid");
        var original = AccessTools.Method(typeof(KSA.Craft), "Update");
        var postfix = new HarmonyMethod(typeof(ManualHandoffLocalRefHooks), "After");
        Look(ref postfix);
        harmony.Patch(original, postfix: postfix);
    }
}
