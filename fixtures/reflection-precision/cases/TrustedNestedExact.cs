// SPDX-License-Identifier: MIT
// As TrustedNestedPrefix, with the exact name: GetMethod("Run") on the nested type finds Inner.Run, which
// starts a program, not the outer type's harmless Run. Expected: Full access, "Starts other programs"
// (H3 review: a lookup on a trusted type reached only the type's own members and its bases', not those of
// its nested types; the game-API map already counted them).
using System.Reflection;

public static class TrustedNestedExact {
    public static void Go() =>
        typeof(HarmonyLib.NestedHost).GetNestedType("Inner")?.GetMethod("Run")?.Invoke(null, null);
}
