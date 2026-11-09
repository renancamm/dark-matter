// SPDX-License-Identifier: MIT
// The same route as TranspilePatchCall, Harmony.Patch(original, transpiler: ...), on a .NET method
// (string.Concat): the original is placed outside the game. Without it the game-target case would
// pass even if this route placed nothing. Expected: Full access, system access, "Rewrites code other
// than the game's with a Harmony transpiler" (G5a).
using System.Collections.Generic;
using HarmonyLib;

public static class PatchCallFrameworkTranspiler {
    static IEnumerable<CodeInstruction> Rewrite(IEnumerable<CodeInstruction> instructions) => instructions;

    public static void Apply() {
        var harmony = new Harmony("example.invalid.patchcallframework");
        var original = AccessTools.Method(typeof(string), nameof(string.Concat), new[] { typeof(string), typeof(string) });
        harmony.Patch(original, transpiler: new HarmonyMethod(AccessTools.Method(typeof(PatchCallFrameworkTranspiler), nameof(Rewrite))));
    }
}
