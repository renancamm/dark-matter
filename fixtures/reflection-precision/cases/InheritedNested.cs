// SPDX-License-Identifier: MIT
// Probe (H7b review): a type nested in the mod's own type derives from a game type, and is found from the outer
// type by GetNestedType, which the walker counts as the outer type. The lookup on it finds the static method it
// inherits, which starts a program (KSA.StartsBase::InheritedRun). Expected: Broad access, "Starts other programs"
// (policy 25: Limited access, nothing: only the outer type's own base types were followed).
using System.Reflection;

internal static class InheritedNestedType {
    internal class Inner : KSA.StartsBase { }
}

public static class InheritedNestedEntry {
    public static void Go() =>
        typeof(InheritedNestedType).GetNestedType("Inner", BindingFlags.NonPublic)!
            .GetMethod("InheritedRun", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)!.Invoke(null, ["example.invalid"]);
}
