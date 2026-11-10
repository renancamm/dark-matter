// SPDX-License-Identifier: MIT
// A reverse patch of a game method given a transpiler (Harmony.ReversePatch(original, standin,
// transpiler)): the copy of the game method is rewritten, and calling the stand-in runs it.
// Expected: Broad access, deep game access ("Rewrites the game's code ..."), that reason only, and the
// game method's label "Changes game saves" (G5a: transpiler placement by target route).
// Policy 38: a transpiler on the game's code is the label "Rewrites parts of the game's code", not a Broad-access reason.
using System.Collections.Generic;
using HarmonyLib;

public static class ReverseWithTranspiler {
    public static void MakeSaveCopy() { }

    static IEnumerable<CodeInstruction> Rewrite(IEnumerable<CodeInstruction> instructions) => instructions;

    public static void Apply() {
        var original = AccessTools.Method(typeof(KSA.GameSaves), nameof(KSA.GameSaves.MakeSave));
        var standin = new HarmonyMethod(AccessTools.Method(typeof(ReverseWithTranspiler), nameof(MakeSaveCopy)));
        Harmony.ReversePatch(original, standin, AccessTools.Method(typeof(ReverseWithTranspiler), nameof(Rewrite)));
        MakeSaveCopy();
    }
}
