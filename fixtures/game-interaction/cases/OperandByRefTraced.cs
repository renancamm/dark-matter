// SPDX-License-Identifier: MIT
// Control: the same write through CodeMatcher.Operand with a game method found by a constant name,
// which the check traces. Expected: Broad access, deep game access ("Rewrites the game's code ..."),
// that reason only, "Changes how the game works" (G5a).
using System.Collections.Generic;
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update))]
public static class SetTracedOperand {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        var matcher = new CodeMatcher(instructions);
        matcher.Operand = AccessTools.Method(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update));
        return matcher.InstructionEnumeration();
    }
}
