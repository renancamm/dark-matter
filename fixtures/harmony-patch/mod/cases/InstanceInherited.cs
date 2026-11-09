// SPDX-License-Identifier: MIT
// Near miss (D7): the patched method is named through a derived type that does not declare it, so Harmony patches
// the base type's method, which runs on instances of other types too. Expected: Broad access, "Uses reflection the
// check cannot trace".
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Rover), nameof(KSA.Rover.Update))]
public static class InstanceInheritedPatch {
    public static void Postfix(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}
