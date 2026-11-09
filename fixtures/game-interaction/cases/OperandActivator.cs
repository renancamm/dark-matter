// SPDX-License-Identifier: MIT
// A transpiler that makes an instruction with Activator.CreateInstance instead of its constructor,
// so the operand is not checked where the constructor is called. The operand is a method the check
// cannot trace. Expected: Full access, "Uses reflection the check cannot trace" (G1a review A3).
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using HarmonyLib;

public static class Src { public static Action Hook; }

[HarmonyPatch(typeof(KSA.Vehicle), "Update")]
public static class MadeByActivator {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        var made = (CodeInstruction)Activator.CreateInstance(typeof(CodeInstruction), OpCodes.Call, (object)Src.Hook.Method);
        return instructions.Prepend(made);
    }
}
