// SPDX-License-Identifier: MIT
// As AccessChecksFramework, with the framework assembly given as a display name
// ("System.Private.CoreLib, PublicKeyToken=..."): the runtime parses the attribute's value as an
// assembly name, so its simple name is what counts. Expected: Broad access, "Uses a part of .NET the
// check does not classify" (H3 review: policy 19 compared the whole string with the framework's
// assembly names and found none).
[assembly: System.Runtime.CompilerServices.IgnoresAccessChecksTo("System.Private.CoreLib, PublicKeyToken=7cec85d7bea7798e")]

namespace System.Runtime.CompilerServices {
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
    internal sealed class IgnoresAccessChecksToAttribute(string assemblyName) : Attribute {
        public string AssemblyName { get; } = assemblyName;
    }
}

public static class AccessChecksDisplayName {
    public static int Length(string text) => text.Length;
}
