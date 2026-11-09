// SPDX-License-Identifier: MIT
// Reflection targets: a constant type name resolves to its capabilities (Limited access);
// a type name built at run time cannot be resolved (Broad access).
using System;

public class ReflectionCases {
    public object ByConstant() {
        var t = Type.GetType("System.Net.Http.HttpClient");
        return Activator.CreateInstance(t);
    }

    public object ByRuntimeName(string part) {
        var t = Type.GetType("System.Net." + part + ".HttpClient");
        return Activator.CreateInstance(t);
    }
}
