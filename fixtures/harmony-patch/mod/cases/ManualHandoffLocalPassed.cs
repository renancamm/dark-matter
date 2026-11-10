// SPDX-License-Identifier: MIT
// Near miss (policy 44): the local holding the HarmonyMethod is also given to another method, which can patch
// another member with it or read its method back. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualHandoffLocalPassedHooks {
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualHandoffLocalPassed {
    static void Note(object what) { }

    public static void Start(bool flag) {
        var harmony = new Harmony("example.invalid");
        var original = AccessTools.Method(typeof(KSA.Craft), "Update");
        var postfix = new HarmonyMethod(typeof(ManualHandoffLocalPassedHooks), "After");
        if (original == null) return;
        Note(postfix);
        harmony.Patch(original, postfix: postfix);
    }
}
