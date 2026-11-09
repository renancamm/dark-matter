// SPDX-License-Identifier: MIT
// Binding flags that are not a constant at the lookup (kept in a field, so they can include
// IgnoreCase): the name matches any casing. Expected: Full access, "Starts other programs" (H1;
// before policy 19, Limited access, no labels).
using System.Reflection;

public static class FlagsNotConstant {
    static BindingFlags flags = BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase;
    public static void Go() =>
        typeof(KSA.Tools.Shell).GetMethod("RUN", flags)?.Invoke(null, ["example.invalid"]);
}
