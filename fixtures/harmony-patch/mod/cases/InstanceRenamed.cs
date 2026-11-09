// SPDX-License-Identifier: MIT
// Near miss (D7): [HarmonyArgument] gives the parameter named __instance one of the original's arguments instead.
// Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Universe), nameof(KSA.Universe.Find))]
public static class InstanceRenamedPatch {
    public static void Postfix([HarmonyArgument("name")] object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}
