// SPDX-License-Identifier: MIT
// Control: invoking a member looked up by constant name on typeof(X). Expected: Limited access.
public class ProvenInvokeCase {
    public static object Run() => typeof(System.Math).GetMethod("Abs", new[] { typeof(int) }).Invoke(null, new object[] { -1 });
}
