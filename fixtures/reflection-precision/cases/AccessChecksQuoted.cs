// SPDX-License-Identifier: MIT
// As AccessChecksDisplayName, with the framework assembly's name quoted ("\"System.Private.CoreLib\""):
// an assembly display name may quote its name, and the runtime parses the attribute's value as one.
// Expected: Full access, "Uses a part of .NET the check does not classify" (H10b review: policy 30
// compared the text up to the first comma, quotes included, with the framework's assembly names and
// found none).
[assembly: System.Runtime.CompilerServices.IgnoresAccessChecksTo("\"System.Private.CoreLib\"")]

namespace System.Runtime.CompilerServices {
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
    internal sealed class IgnoresAccessChecksToAttribute(string assemblyName) : Attribute {
        public string AssemblyName { get; } = assemblyName;
    }
}

public static class AccessChecksQuoted {
    public static int Length(string text) => text.Length;
}
