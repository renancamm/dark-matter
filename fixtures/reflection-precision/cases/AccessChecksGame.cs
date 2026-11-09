// SPDX-License-Identifier: MIT
// Control for AccessChecksFramework: IgnoresAccessChecksTo the game (as a publicizer emits). The
// game-API map covers the game's non-public members too, so a direct call to one gets what that
// member can do. Expected: Limited access, no labels.
[assembly: System.Runtime.CompilerServices.IgnoresAccessChecksTo("KSA")]

namespace System.Runtime.CompilerServices {
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
    internal sealed class IgnoresAccessChecksToAttribute(string assemblyName) : Attribute {
        public string AssemblyName { get; } = assemblyName;
    }
}

public static class AccessChecksGame {
    public static void Draw(string text) => KSA.UiText.Draw(text);
}
