// SPDX-License-Identifier: MIT
// Negative for H7's member-scoped reach (F1, guard 2): GetMember with a prefix pattern ("Ru*") on the
// mod's own type finds Run, whose Type parameter is then what the reflective call passes. Expected: Broad
// access, "Uses reflection the check cannot trace" (a prototype that compared "Ru*" literally gave
// Limited access; H1a-review probe XF1GetMemberStar).
using System;
using System.Reflection;

internal static class RG {
    private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
}

public static class F1StarEntry {
    public static void Go(string text) {
        var ms = typeof(RG).GetMember("Ru*", BindingFlags.NonPublic | BindingFlags.Static);
        (ms[0] as MethodInfo)?.Invoke(null, [typeof(KSA.UiText), text]);
    }
}
