// SPDX-License-Identifier: MIT
// Near miss (D7): the patch method is also handed to Harmony by name (new HarmonyMethod(type, name)), to patch
// whatever member the mod chooses. Expected: Broad access, "Uses reflection the check cannot trace".
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Craft), nameof(KSA.Craft.Update))]
public static class InstanceManualPatch {
    public static void Postfix(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
    public static HarmonyMethod Again() => new(typeof(InstanceManualPatch), "Postfix");
}
