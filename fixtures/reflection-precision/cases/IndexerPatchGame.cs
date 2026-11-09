// SPDX-License-Identifier: MIT
// Probe (H7 review): a Harmony getter patch without a name patches the type's indexer getter (Harmony's
// PatchTools.GetOriginalMethod: DeclaredIndexerGetter). The prefix changes what KSA.Launcher's renamed
// indexer starts. Expected: Full access, "Starts other programs" (before: the attribute named no target,
// Limited access).
using HarmonyLib;

[HarmonyPatch(typeof(KSA.Launcher), MethodType.Getter)]
public static class LauncherIndexerPatch {
    public static void Prefix(ref string file) => file = "example.invalid";
}
