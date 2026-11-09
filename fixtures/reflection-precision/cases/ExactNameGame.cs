// SPDX-License-Identifier: MIT
// Control for IgnoreCaseGame and the other by-name cases: the same game method looked up by its
// exact name and invoked. Expected: Broad access, "Starts other programs".
using System.Reflection;

public static class ExactNameGame {
    public static void Go() =>
        typeof(KSA.Tools).GetNestedType("Shell")?.GetMethod("Run", BindingFlags.Public | BindingFlags.Static)?.Invoke(null, ["example.invalid"]);
}
