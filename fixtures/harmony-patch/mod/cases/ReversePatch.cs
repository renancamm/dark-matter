// SPDX-License-Identifier: MIT
// A reverse patch copies the game method's code into the stub, so calling the stub runs it.
// Expected: Known access with the method's game-API label ("Changes game saves").
using HarmonyLib;

public static class ReversePatchCase {
    [HarmonyReversePatch]
    [HarmonyPatch(typeof(KSA.GameSaves), "MakeSave")]
    public static void MakeSaveCopy() { }
}
