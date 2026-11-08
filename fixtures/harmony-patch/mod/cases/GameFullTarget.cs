// SPDX-License-Identifier: MIT
// A prefix on a game method that starts whatever its caller names (KSA.Links.Open in the game
// stand-in). The prefix sees and can change the argument, so the patch can start any program.
// Expected with the game profile: Full access ("Starts other programs").
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Links), "Open")]
public static class GameFullTargetPatch {
    public static void Prefix(ref string target) => target = "calc.exe";
}
