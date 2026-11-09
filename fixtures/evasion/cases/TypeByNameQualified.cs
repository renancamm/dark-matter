// SPDX-License-Identifier: MIT
// H9 negative: a name with an assembly part can make the runtime load that assembly, even when the result
// is only tested for null: still "Calls code that was not analyzed".
using HarmonyLib;

public static class TypeByNameQualified {
    public static bool Installed => AccessTools.TypeByName("OtherMod.Feature, OtherMod") != null;
}
