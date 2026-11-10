// SPDX-License-Identifier: MIT
// Near miss (policy 44): another patch method of the mod takes __instance by reference, declared as object. Harmony
// hands it the address of the instance argument, so it can store any object there before the postfix is given it.
// Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

internal static class ManualInstanceReplacedHooks {
    internal static void Before(ref object __instance) => __instance = KSA.Universe.Instance.Anything;
    internal static void After(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}

public static class ManualInstanceReplaced {
    public static void Start() {
        var harmony = new Harmony("example.invalid");
        harmony.Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), prefix: new HarmonyMethod(typeof(ManualInstanceReplacedHooks), "Before"));
        harmony.Patch(AccessTools.Method(typeof(KSA.Craft), "Update"), postfix: new HarmonyMethod(typeof(ManualInstanceReplacedHooks), "After"));
    }
}
