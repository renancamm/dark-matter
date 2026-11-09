// SPDX-License-Identifier: MIT
// Probe case: a MethodInfo field written once from a constant lookup and once from an enumerated
// type, then invoked through the field. Expected: Broad access.
using System.Linq;
using System.Reflection;

public class FieldUntrackedCase {
    static MethodInfo target = typeof(System.Math).GetMethod("Abs", new[] { typeof(int) });

    public static void Retarget(string typeName, string method) =>
        target = typeof(object).Assembly.GetTypes().First(t => t.FullName == typeName).GetMethod(method);

    public static object Run(object[] args) => target.Invoke(null, args);
}
