// SPDX-License-Identifier: MIT
// Control: a transpiler applied with Harmony.Patch(original, transpiler: ...) to a game method found
// by a constant name. The original is placed in the game's code, as for the attribute form
// (TranspilerOperand). Expected: Broad access, deep game access ("Rewrites the game's code ..."), that
// reason only, "Changes how the game works" (G5a: transpiler placement by target route).
// Policy 38: a transpiler on the game's code is the label "Rewrites parts of the game's code", not a Broad-access reason.
using System.Collections.Generic;
using HarmonyLib;

public static class PatchCallTranspiler {
    static IEnumerable<CodeInstruction> Rewrite(IEnumerable<CodeInstruction> instructions) => instructions;

    public static void Apply() {
        var harmony = new Harmony("example.invalid.patchcall");
        var original = AccessTools.Method(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update));
        harmony.Patch(original, transpiler: new HarmonyMethod(AccessTools.Method(typeof(PatchCallTranspiler), nameof(Rewrite))));
    }
}
