// SPDX-License-Identifier: MIT
// Benign control for H7's member-scoped reach (F1): GetFields on a type reaches no method of it but its
// type initializer, so its private helper's Type parameter is what its callers pass (KSA.UiText, whose
// Draw is harmless). Expected: Limited access, no labels (before H7: Full access, "Uses reflection the
// check cannot trace": every method of a type reached by reflection could be given any argument).
using System;
using System.Reflection;

internal static class Settings {
    internal static int A;
    private static void Use(Type t) => t.GetMethod("Draw")?.Invoke(null, ["x"]);
    internal static void Go() => Use(typeof(KSA.UiText));
}

public static class F1BenignEntry {
    public static int Go() { Settings.Go(); return typeof(Settings).GetFields(BindingFlags.NonPublic | BindingFlags.Static).Length; }
}
