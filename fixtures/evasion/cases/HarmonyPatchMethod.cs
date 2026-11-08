// SPDX-License-Identifier: MIT
// Probe case: a Harmony patch method taken from an object's run-time type. Harmony runs patch
// methods, so this calls whatever the object's type has. Expected: Full access.
using HarmonyLib;

public class HarmonyPatchMethodCase {
    public static HarmonyMethod Run(object o, string method) => new HarmonyMethod(o.GetType().GetMethod(method));
}
