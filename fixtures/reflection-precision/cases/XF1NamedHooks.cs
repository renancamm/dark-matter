// SPDX-License-Identifier: MIT
// Benign control for H7's member-scoped reach (F1), in the shape of a real mod's hook installer: a patch
// helper looks its own prefix up by a name every caller passes as a constant, and is given the game
// member to hook as a traced MethodInfo. The helper itself is never named by a lookup, so its parameters
// are what its callers pass. Expected: Limited access, no labels (before H7: Full access, "Uses
// reflection the check cannot trace": the lookup on Hooks made every method of it reachable).
using System.Reflection;

internal static class Hooks {
    static void Patch(MethodInfo target, string prefix) {
        typeof(Hooks).GetMethod(prefix, BindingFlags.NonPublic | BindingFlags.Static)?.Invoke(null, null);
        target.Invoke(null, ["hooked"]);
    }
    static void BeforePopups() { }
    static void AfterLoad() { }
    internal static void Install() {
        Patch(typeof(KSA.UiText).GetMethod("Draw")!, "BeforePopups");
        Patch(typeof(KSA.UiText).GetMethod("Draw")!, "AfterLoad");
    }
}

public static class HooksEntry {
    public static void Go() => Hooks.Install();
}
