// SPDX-License-Identifier: MIT
// Probe case: a Harmony Traverse on a type named at run time. Expected: Broad access.
using HarmonyLib;

public class TraverseByRuntimeNameCase {
    public static object Run(string type) => Traverse.CreateWithType(type).Method("Start").GetValue();
}
