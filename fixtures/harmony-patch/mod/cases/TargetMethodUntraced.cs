// SPDX-License-Identifier: MIT
// The patch target comes from a TargetMethod that picks a method of a type found by enumeration.
// Harmony replaces whatever it returns. Expected: Full access.
using System.Reflection;
using HarmonyLib;

[HarmonyPatch]
public static class TargetMethodUntracedPatch {
    static MethodBase TargetMethod() => typeof(object).Assembly.GetTypes()[7].GetMethod("Start");
    public static void Prefix() { }
}
