// SPDX-License-Identifier: MIT
// Control: a prefix on a game method. Expected: Limited access, "Changes how the game works".
using HarmonyLib;

[HarmonyPatch(typeof(KSA.GameSaves), nameof(KSA.GameSaves.MakeSave))]
public static class GameTargetPatch {
    public static bool Prefix() => true;
}
