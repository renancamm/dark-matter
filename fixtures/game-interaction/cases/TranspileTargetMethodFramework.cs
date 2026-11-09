// SPDX-License-Identifier: MIT
// The same route as TranspileTargetMethod, a TargetMethod() of a class with a transpiler, returning a
// .NET method (string.Concat). Expected: Full access, system access, "Rewrites code other than the
// game's with a Harmony transpiler" (G5a).
using System.Collections.Generic;
using System.Reflection;
using HarmonyLib;

[HarmonyPatch]
public static class TargetMethodFrameworkTranspiler {
    static MethodBase TargetMethod() => AccessTools.Method(typeof(string), nameof(string.Concat), new[] { typeof(string), typeof(string) });
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions;
}
