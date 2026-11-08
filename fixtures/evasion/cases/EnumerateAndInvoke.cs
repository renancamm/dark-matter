// SPDX-License-Identifier: MIT
// Probe case: the Type comes from enumeration, not from a name. Expected: Full access.
using System.Reflection;

public class EnumerateAndInvokeCase {
    public static object Run(string typeName, string method, object[] args) {
        foreach (var t in typeof(object).Assembly.GetTypes())
            if (t.FullName == typeName)
                return t.GetMethod(method, new[] { typeof(string) }).Invoke(null, args);
        return null;
    }
}
