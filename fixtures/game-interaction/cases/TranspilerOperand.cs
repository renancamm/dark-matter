// SPDX-License-Identifier: MIT
// Control: a Harmony transpiler that points the game method's calls at the mod's own method, found
// by a constant name. The game method Harmony compiles is not one the check has read, so this is
// deep game access ("Rewrites the game's code ..."), not "Builds code at run time". Expected: Broad
// access, deep game access, that reason only, "Changes how the game works".
// Policy 38: a transpiler on the game's code is the label "Rewrites parts of the game's code", not a Broad-access reason.
using System.Collections.Generic;
using System.Reflection.Emit;
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Vehicle), "Update")]
public static class VehicleUpdateTranspiler {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        var replacement = AccessTools.Method(typeof(VehicleUpdateTranspiler), nameof(Replacement));
        foreach (var instruction in instructions) {
            if (instruction.opcode == OpCodes.Call) instruction.operand = replacement;
            yield return instruction;
        }
    }

    static void Replacement() { }
}
