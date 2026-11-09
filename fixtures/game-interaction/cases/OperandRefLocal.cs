// SPDX-License-Identifier: MIT
// A transpiler that keeps the reference CodeMatcher.Operand returns in a local and writes through it
// later. The operand is a method the check cannot trace. Expected: Broad access, "Uses reflection the
// check cannot trace" (G5a).
using System;
using System.Collections.Generic;
using HarmonyLib;

public static class Src { public static Action Hook; }

[HarmonyPatch(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update))]
public static class SetThroughRefLocal {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        var matcher = new CodeMatcher(instructions);
        ref object operand = ref matcher.Operand;
        operand = Src.Hook.Method;
        return matcher.InstructionEnumeration();
    }
}
