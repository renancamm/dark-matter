// SPDX-License-Identifier: MIT
// H9 negative: the type found by name is kept in a field (and tested for null there), where any code can
// use it later: still "Calls code that was not analyzed".
using System;
using HarmonyLib;

public static class TypeByNameField {
    static readonly Type? Found = AccessTools.TypeByName("OtherMod.Feature");
    public static bool Installed => Found != null;
}
