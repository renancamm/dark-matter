// SPDX-License-Identifier: MIT
// A transpiler that writes an instruction's operand through the reference CodeMatcher.Operand
// returns. The operand is a method the check cannot trace. Expected: Broad access, "Uses reflection the
// check cannot trace" (G5a).
using System;
using System.Collections.Generic;
using HarmonyLib;

public static class Src { public static Action Hook; }

[HarmonyPatch(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update))]
public static class SetThroughOperand {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        var matcher = new CodeMatcher(instructions);
        matcher.Operand = Src.Hook.Method;
        return matcher.InstructionEnumeration();
    }
}
