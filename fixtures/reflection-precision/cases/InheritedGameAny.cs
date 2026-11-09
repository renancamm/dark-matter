// SPDX-License-Identifier: MIT
// Probe (H7 review, H7b): as InheritedGame, with an unnamed lookup (GetMethods), which returns the inherited
// members too. Expected: Full access, "Starts other programs" (before: Limited access, nothing).
using System.Reflection;

internal class InheritedGameAnyType : KSA.StartsBase { }

public static class InheritedGameAnyEntry {
    public static void Go() {
        foreach (var m in typeof(InheritedGameAnyType).GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy))
            m.Invoke(null, ["example.invalid"]);
    }
}
