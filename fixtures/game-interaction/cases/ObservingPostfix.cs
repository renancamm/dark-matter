// SPDX-License-Identifier: MIT
// Control: a postfix on a game method that starts whatever its caller names (KSA.Links.Open in the
// game stand-in). It returns nothing and only sees the argument as a string, so it cannot change
// what the method starts. Expected: Limited access, "Changes how the game works". (A prefix that takes
// the argument by reference, harmony-patch/GameFullTarget, stays Broad access.)
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Links), "Open")]
public static class LinkLogger {
    public static int Opened;

    public static void Postfix(string target) {
        if (target.Length > 0) Opened++;
    }
}
