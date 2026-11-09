// SPDX-License-Identifier: MIT
// Control for IndexerRenamedGame (H7 review): a conventional indexer (get_Item) reaches that accessor only,
// not the type's other members (KSA.Slots.Reset starts a program). Expected: Limited access, with only the
// label every use of AccessTools has, "Changes how the game works" (unchanged).
using HarmonyLib;

public static class IndexerPlainEntry {
    public static object Go(KSA.Slots slots) => AccessTools.Indexer(typeof(KSA.Slots)).GetValue(slots, [1]);
}
