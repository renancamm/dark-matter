// SPDX-License-Identifier: MIT
// Control: a member looked up by constant name, kept in a local and checked for null before it
// is invoked; a Type field read by a lookup through the field; a member kept in an
// auto-property. Expected: Limited access.
using System;
using System.Reflection;

public class ProvenBranchCase {
    static readonly Type MathType = typeof(Math);
    static MethodInfo Max { get; } = typeof(Math).GetMethod("Max", new[] { typeof(int), typeof(int) });

    public static object Run(bool negative) {
        MethodInfo m = null;
        if (negative) m = MathType.GetMethod("Abs", new[] { typeof(int) });
        if (m == null) return null;
        return m?.Invoke(null, new object[] { -1 });
    }

    public static object ViaProperty() => Max.Invoke(null, new object[] { 1, 2 });
}
