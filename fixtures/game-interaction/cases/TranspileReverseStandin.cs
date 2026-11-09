// SPDX-License-Identifier: MIT
// A reverse patch by attribute whose stand-in carries its own transpiler (a local function taking
// and returning Harmony instructions, which Harmony applies to the copy of the game method).
// Expected: Full access, deep game access ("Rewrites the game's code ..."), that reason only, and the
// game method's label "Changes game saves" (G5a: transpiler placement by target route).
using System.Collections.Generic;
using System.Linq;
using HarmonyLib;

public static class ReverseStandinTranspiler {
    [HarmonyReversePatch]
    [HarmonyPatch(typeof(KSA.GameSaves), nameof(KSA.GameSaves.MakeSave))]
    public static void MakeSaveCopy() {
        _ = Transpiler(null);
        static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions.Skip(1);
    }
}
