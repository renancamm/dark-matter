// SPDX-License-Identifier: MIT
// The real API: a Harmony transpiler on a .NET method (string.Concat), not a game method. Deep game
// access covers a transpiler only because what it can change is bounded to the game's code; rewriting the
// framework is not. Expected: Full access, system access, "Rewrites code other than the game's with a Harmony transpiler".
using System.Collections.Generic;
using HarmonyLib;

[HarmonyPatch(typeof(string), nameof(string.Concat), typeof(string), typeof(string))]
public static class ConcatTranspiler {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions;
}
