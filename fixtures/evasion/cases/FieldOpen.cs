// SPDX-License-Identifier: MIT
// Probe case: a public, writable MethodInfo field that only this assembly assigns from a constant
// lookup, invoked through the field. Another assembly can assign it. Expected: Full access.
using System.Reflection;

public class FieldOpenCase {
    public static MethodInfo Target = typeof(System.Math).GetMethod("Abs", new[] { typeof(int) });
    public static object Run() => Target.Invoke(null, new object[] { -1 });
}
