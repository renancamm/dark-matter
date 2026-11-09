// SPDX-License-Identifier: MIT
// A mod with a Harmony transpiler (it can change the game's code) that reaches, by GetMember, a nested
// type of the game's RequiresRestartPopup, which the policy exempts from process-start as a whole
// ("KSA.RequiresRestartPopup/": the game restarting its own executable). Once game code can be rewritten
// that exemption is given back. Expected: Full access, deep game access ("Rewrites ...") and "Starts
// other programs" (H3 review: policy 19 compared the exemption's nested-type name, empty for a pattern
// that ends at the '/', with the name looked up, and gave nothing back).
using System.Collections.Generic;
using System.Linq;
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Vehicle), "Update")]
public static class DropUpdate {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) => instructions.Skip(1);
}

public static class Use {
    public static int Go() => typeof(KSA.RequiresRestartPopup).GetMember("Restarter").Length;
}
