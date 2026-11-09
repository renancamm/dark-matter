// SPDX-License-Identifier: MIT
// A transpiler added with PatchProcessor.AddTranspiler. The check does not link the processor's
// original (here a game method) to the transpiler, so the rewritten code is not placed in the game.
// Expected: Full access, system access, "Rewrites code other than the game's with a Harmony
// transpiler" (G5a: transpiler placement by target route).
using System.Collections.Generic;
using HarmonyLib;

public static class ProcessorTranspiler {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions;

    public static void Apply() {
        var harmony = new Harmony("example.invalid.processor");
        harmony.CreateProcessor(AccessTools.Method(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update)))
            .AddTranspiler(new HarmonyMethod(AccessTools.Method(typeof(ProcessorTranspiler), nameof(Transpiler))))
            .Patch();
    }
}
