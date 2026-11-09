// SPDX-License-Identifier: MIT
// A transpiler that returns an instruction of the mod's own CodeInstruction subclass. The operand it
// gives the base constructor is inert; the subclass itself is what the check cannot follow. Expected:
// Broad access, "Uses reflection the check cannot trace" (G5a).
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using HarmonyLib;

public class TaggedInstruction : CodeInstruction {
    public TaggedInstruction() : base(OpCodes.Nop, null) { }
}

[HarmonyPatch(typeof(KSA.Vehicle), nameof(KSA.Vehicle.Update))]
public static class UsesSubclass {
    static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> instructions) =>
        instructions.Prepend(new TaggedInstruction());
}
