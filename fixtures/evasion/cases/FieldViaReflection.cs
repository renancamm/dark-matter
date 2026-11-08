// SPDX-License-Identifier: MIT
// Probe case: the MethodInfo field is assigned from a constant lookup, but overwritten through
// FieldInfo.SetValue with an enumerated member before it is invoked. Expected: Full access.
using System.Linq;
using System.Reflection;

public class FieldViaReflectionCase {
    static MethodInfo Target = typeof(System.Math).GetMethod("Abs", new[] { typeof(int) });

    public static void Retarget(object member) =>
        typeof(FieldViaReflectionCase).GetField("Target", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, member);

    public static object Run() => Target.Invoke(null, new object[] { -1 });
}
