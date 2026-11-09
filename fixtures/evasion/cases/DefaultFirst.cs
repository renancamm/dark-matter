// SPDX-License-Identifier: MIT
// Probe case: FirstOrDefault with a default value on an empty array returns the default, a method
// the check cannot trace, which is then invoked. Expected: Broad access, "Uses reflection the check
// cannot trace" (G1a review A7).
using System;
using System.Linq;
using System.Reflection;

public static class Src { public static Action Hook; }

public static class FirstOrDefaultValue {
    public static void Go() => Array.Empty<MethodInfo>().FirstOrDefault(Src.Hook.Method).Invoke(null, null);
}
