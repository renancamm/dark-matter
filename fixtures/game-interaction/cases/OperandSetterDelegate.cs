// SPDX-License-Identifier: MIT
// A transpiler that hands an instruction an operand through a delegate to CodeMatcher's setter,
// where the check's operand test at the call does not run. The operand is a method the check
// cannot trace. Expected: Full access, "Uses reflection the check cannot trace" (G1a review A3).
using System;
using System.Collections.Generic;
using HarmonyLib;

public static class Src { public static Action Hook; }

[HarmonyPatch(typeof(KSA.Vehicle), "Update")]
public static class SetThroughDelegate {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        var matcher = new CodeMatcher(instructions);
        Func<object, CodeMatcher> set = matcher.SetOperandAndAdvance;
        set(Src.Hook.Method);
        return matcher.InstructionEnumeration();
    }
}
