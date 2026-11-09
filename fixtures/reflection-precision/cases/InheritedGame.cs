// SPDX-License-Identifier: MIT
// Probe (H7 review, H7b): reflection on the mod's own type finds a static method it inherits from a game base
// type, which starts a program (KSA.StartsBase::InheritedRun). Expected: Broad access, "Starts other programs"
// (before: Limited access, nothing: a lookup on a mod type reached only the mod's own code).
using System.Reflection;

internal class InheritedGameType : KSA.StartsBase { }

public static class InheritedGameEntry {
    public static void Go() =>
        typeof(InheritedGameType).GetMethod("InheritedRun", BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)!
            .Invoke(null, ["example.invalid"]);
}
