// SPDX-License-Identifier: MIT
// H9 (policy 29): a type looked up by a name with no assembly part only to see whether another mod is
// loaded (AdvancedFlightComputer's check for a standalone copy of a feature) finds a type or null and runs
// nothing: Limited access (before H9: "Calls code that was not analyzed"). The negatives use the result.
using System;
using HarmonyLib;

public static class TypeByNameNullTest {
    public static void WarnIfInstalled() {
        if (AccessTools.TypeByName("OtherMod.Feature") != null) Console.WriteLine("remove the standalone copy");
        if (AccessTools.TypeByName("OtherMod.Extra") is null) Console.WriteLine("not installed");
    }
    public static bool Prepare() => AccessTools.TypeByName("OtherMod.Other") != null;
}
