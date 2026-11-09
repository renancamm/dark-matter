// SPDX-License-Identifier: MIT
// [assembly: IgnoresAccessChecksTo("System.Private.CoreLib")]: the runtime then lets this assembly
// call non-public framework members directly, which the policy (it classifies framework members by
// name, not by visibility) does not account for. Expected: Full access, "Uses a part of .NET the
// check does not classify" (before policy 19 the attribute was not read: Limited access).
// Control: AccessChecksGame.
[assembly: System.Runtime.CompilerServices.IgnoresAccessChecksTo("System.Private.CoreLib")]

namespace System.Runtime.CompilerServices {
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
    internal sealed class IgnoresAccessChecksToAttribute(string assemblyName) : Attribute {
        public string AssemblyName { get; } = assemblyName;
    }
}

public static class AccessChecksFramework {
    public static int Length(string text) => text.Length;
}
