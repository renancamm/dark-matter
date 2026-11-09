// SPDX-License-Identifier: MIT
// Control: a Harmony Traverse from typeof(X) calling a method by name. Expected: Limited access.
using HarmonyLib;

public class TraverseByNameCase {
    public static object Run() => Traverse.Create(typeof(System.Math)).Method("Abs", -1).GetValue();
}
