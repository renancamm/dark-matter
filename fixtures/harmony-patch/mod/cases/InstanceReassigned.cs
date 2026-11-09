// SPDX-License-Identifier: MIT
// Near miss (D7): the patch method stores another value into __instance before using it. Expected: Broad access,
// "Uses reflection the check cannot trace".
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Craft), nameof(KSA.Craft.Update))]
public static class InstanceReassignedPatch {
    public static object Other = "text";

    public static void Postfix(object __instance) {
        __instance = Other;
        __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
    }
}
