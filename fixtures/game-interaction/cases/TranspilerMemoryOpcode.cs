// SPDX-License-Identifier: MIT
// Control (policy 38): a Harmony transpiler on a game method that adds an instruction storing through an
// address. What that instruction does in the method Harmony compiles is not checked as the mod's own
// instructions are. Expected: Broad access, deep game access ("Reads or writes memory directly"), with the
// label "Rewrites parts of the game's code". Analyzed only, never run.
using System.Collections.Generic;
using System.Reflection.Emit;
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Vehicle), "Update")]
public static class VehicleUpdateStore {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) {
        foreach (var instruction in instructions) {
            if (instruction.opcode == OpCodes.Ret) {
                yield return new CodeInstruction(OpCodes.Ldarg_0);
                yield return new CodeInstruction(OpCodes.Ldc_I4_0);
                yield return new CodeInstruction(OpCodes.Stind_I4);
            }
            yield return instruction;
        }
    }
}
