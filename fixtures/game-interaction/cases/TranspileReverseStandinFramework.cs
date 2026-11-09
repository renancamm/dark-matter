// SPDX-License-Identifier: MIT
// The same route as TranspileReverseStandin, a reverse patch by attribute whose stand-in carries its own
// transpiler, on a .NET method (string.Concat). Expected: Broad access, system access, "Rewrites code
// other than the game's with a Harmony transpiler" (G5a).
using System.Collections.Generic;
using System.Linq;
using HarmonyLib;

public static class ReverseStandinFrameworkTranspiler {
    [HarmonyReversePatch]
    [HarmonyPatch(typeof(string), nameof(string.Concat), typeof(string), typeof(string))]
    public static string ConcatCopy(string a, string b) {
        _ = Transpiler(null);
        static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions.Skip(1);
        return a;
    }
}
