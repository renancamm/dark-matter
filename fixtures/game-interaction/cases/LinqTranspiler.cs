// SPDX-License-Identifier: MIT
// A Harmony transpiler that only drops instructions of the game method with LINQ: it uses no
// CodeInstruction member, so before policy 15 nothing counted it as a rewrite. The patched game
// method is the browser opener whose exemption assumes the game's own check runs. Expected: Broad
// access, deep game access ("Rewrites the game's code ..."), and "Starts other programs" given back
// on the opener (G1a review A1).
// Policy 38: a transpiler on the game's code is the label "Rewrites parts of the game's code", not a Broad-access reason.
using System.Collections.Generic;
using System.Linq;
using HarmonyLib;

[HarmonyPatch(typeof(KSA.UpdateAvailablePopup), "OpenBrowser")]
public static class DropCheck {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions.Skip(4);
}

public static class Use {
    public static void Go() => KSA.UpdateAvailablePopup.OpenBrowser("https://example.invalid/");
}
