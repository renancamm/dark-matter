// SPDX-License-Identifier: MIT
// Control: TargetMethod returns a game method looked up by a constant name. Expected: Known access.
using System.Reflection;
using HarmonyLib;

[HarmonyPatch]
public static class TargetMethodTracedPatch {
    [HarmonyTargetMethod]
    static MethodBase Target() => AccessTools.Method(typeof(KSA.GameSaves), "MakeSave");
    public static void Prefix() { }
}
