// SPDX-License-Identifier: MIT
// Control: a patch class with a transpiler whose target comes from TargetMethod(), a game method
// found by a constant name. Expected: Broad access, deep game access ("Rewrites the game's code ..."),
// that reason only, "Changes how the game works" (G5a: transpiler placement by target route).
// Policy 38: a transpiler on the game's code is the label "Rewrites parts of the game's code", not a Broad-access reason.
using System.Collections.Generic;
using System.Reflection;
using HarmonyLib;

[HarmonyPatch]
public static class TargetMethodTranspiler {
    static MethodBase TargetMethod() => AccessTools.Method(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update));
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions;
}
