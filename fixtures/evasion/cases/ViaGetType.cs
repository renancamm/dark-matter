// SPDX-License-Identifier: MIT
// Probe case: the Type is the instance's own type. Expected: Broad access.
public class ViaGetTypeCase {
    public static object Run(object o, string method) => o.GetType().GetMethod(method).Invoke(o, null);
}
