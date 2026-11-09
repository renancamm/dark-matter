// SPDX-License-Identifier: MIT
// A transpiler on the mod's own method: the check reads the mod's code as written, and what it
// proved on it does not hold once it is rewritten. Expected: Full access, system access, "Rewrites
// code other than the game's with a Harmony transpiler" (G5a: transpiler placement by target route).
using System.Collections.Generic;
using HarmonyLib;

public static class OwnCode {
    public static void Work() { }
}

[HarmonyPatch(typeof(OwnCode), nameof(OwnCode.Work))]
public static class OwnCodeTranspiler {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions;
}
