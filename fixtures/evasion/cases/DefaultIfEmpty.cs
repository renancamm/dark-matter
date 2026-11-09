// SPDX-License-Identifier: MIT
// Probe case: DefaultIfEmpty with a default value on an empty array yields the default, a method
// the check cannot trace, which is then invoked. Expected: Full access, "Uses reflection the check
// cannot trace" (G1a review A7).
using System;
using System.Linq;
using System.Reflection;

public static class Src { public static Action Hook; }

public static class DefaultIfEmptyValue {
    public static void Go() => Array.Empty<MethodInfo>().DefaultIfEmpty(Src.Hook.Method).First().Invoke(null, null);
}
