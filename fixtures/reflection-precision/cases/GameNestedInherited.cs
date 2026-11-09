// SPDX-License-Identifier: MIT
// Probe (H7b review): the game's KSA.NestedStarts has a nested type deriving from KSA.StartsBase; found from the
// outer type by GetNestedType (counted as the outer type), the lookup finds the static method it inherits, which
// starts a program. Expected: Full access, "Starts other programs" (policy 25: Limited access, nothing: only the
// game members of the outer type and of the types nested in it were reached, not what those inherit).
using System.Reflection;

public static class GameNestedInheritedEntry {
    public static void Go() =>
        typeof(KSA.NestedStarts).GetNestedType("Starter")!
            .GetMethod("InheritedRun", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)!.Invoke(null, ["example.invalid"]);
}
