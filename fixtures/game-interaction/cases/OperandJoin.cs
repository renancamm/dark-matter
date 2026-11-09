// SPDX-License-Identifier: MIT
// An instruction operand that is a string on one path and a method the check cannot trace on the
// other: the join is not an inert string. Expected: Broad access, "Uses reflection the check cannot
// trace" (G1a review A4).
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using HarmonyLib;

public static class Src { public static Action Hook; public static string Name = ""; }

[HarmonyPatch(typeof(KSA.Vehicle), "Update")]
public static class StringOrMethod {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) =>
        instructions.Prepend(new CodeInstruction(OpCodes.Call, Src.Name.Length > 99 ? "x" : Src.Hook.Method));
}
