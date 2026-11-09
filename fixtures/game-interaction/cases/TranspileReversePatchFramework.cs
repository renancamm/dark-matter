// SPDX-License-Identifier: MIT
// The same route as TranspileReversePatch, Harmony.ReversePatch(original, standin, transpiler), with a
// .NET method (string.Concat) as the original. Expected: Full access, system access, "Rewrites code
// other than the game's with a Harmony transpiler" (G5a).
using System.Collections.Generic;
using HarmonyLib;

public static class ReverseFrameworkTranspiler {
    public static string ConcatCopy(string a, string b) => a;

    static IEnumerable<CodeInstruction> Rewrite(IEnumerable<CodeInstruction> instructions) => instructions;

    public static void Apply() {
        var original = AccessTools.Method(typeof(string), nameof(string.Concat), new[] { typeof(string), typeof(string) });
        var standin = new HarmonyMethod(AccessTools.Method(typeof(ReverseFrameworkTranspiler), nameof(ConcatCopy)));
        Harmony.ReversePatch(original, standin, AccessTools.Method(typeof(ReverseFrameworkTranspiler), nameof(Rewrite)));
    }
}
