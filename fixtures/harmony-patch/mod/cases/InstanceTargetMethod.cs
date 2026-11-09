// SPDX-License-Identifier: MIT
// Near miss (D7): the target comes from a TargetMethod, not from the attributes. Expected: Full access, "Uses
// reflection the check cannot trace".
using System.Reflection;
using HarmonyLib;

[HarmonyPatch]
public static class InstanceTargetMethodPatch {
    static MethodBase TargetMethod() => AccessTools.Method(typeof(KSA.Craft), "Update");
    public static void Postfix(object __instance) => __instance.GetType().GetMethod("Rename")!.Invoke(__instance, ["name"]);
}
