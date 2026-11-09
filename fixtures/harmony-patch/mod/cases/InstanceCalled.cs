// SPDX-License-Identifier: MIT
// Near miss (D7): the mod's own code also calls the patch method, with any object. Expected: Full access, "Uses
// reflection the check cannot trace".
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Craft), nameof(KSA.Craft.Update))]
public static class InstanceCalledPatch {
    public static void Postfix(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
    public static void Also() => Postfix("text");
}
