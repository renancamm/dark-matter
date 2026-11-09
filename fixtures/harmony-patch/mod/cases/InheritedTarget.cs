// SPDX-License-Identifier: MIT
// [HarmonyPatch] split across classes: the base class names the type, the derived patch class the
// method. Harmony merges them (inherit: true), so the target is KSA.Links.Open, which starts whatever
// its caller names; neither attribute names a target alone. Expected with the game profile: Full
// access ("Starts other programs") (G5a).
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Links))]
public class LinksPatchBase { }

[HarmonyPatch(nameof(KSA.Links.Open))]
public class LinksOpenPatch : LinksPatchBase {
    public static void Prefix(ref string target) => target = "calc.exe";
}
