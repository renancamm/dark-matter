// SPDX-License-Identifier: MIT
// Control: Harmony's TargetMethods yields the game methods to patch, each looked up by a constant
// name. Expected: Limited access, "Changes how the game works".
using System.Collections.Generic;
using System.Reflection;
using HarmonyLib;

[HarmonyPatch]
public static class VehicleUpdatePatch {
    static IEnumerable<MethodBase> TargetMethods() {
        yield return AccessTools.Method(typeof(KSA.Vehicle), "Update");
        yield return AccessTools.Method(typeof(KSA.Vehicle), "get_Mass");
    }

    public static void Postfix() { }
}
