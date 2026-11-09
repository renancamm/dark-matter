// SPDX-License-Identifier: MIT
// Control: invoking a MethodInfo kept in a static field, written once from a constant lookup. Expected: Limited access.
using System.Reflection;

public class ProvenFieldCase {
    static readonly MethodInfo Abs = typeof(System.Math).GetMethod("Abs", new[] { typeof(int) });
    public static object Run() => Abs.Invoke(null, new object[] { -1 });
}
