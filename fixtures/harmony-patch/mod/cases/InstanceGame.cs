// SPDX-License-Identifier: MIT
// Probe (D7, policy 35): a postfix's __instance declared as object is the instance of the game method it patches,
// named by typeof in the attribute and declared by that type alone: that type or a derived one. Expected: Full
// access, deep game access only, "Uses your clipboard" (before: "Uses reflection the check cannot trace").
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Craft), nameof(KSA.Craft.Update))]
public static class InstanceGamePatch {
    public static void Postfix(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}
