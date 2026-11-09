// SPDX-License-Identifier: MIT
// A game type found by name alone (AccessTools.TypeByName searches every loaded assembly), then a
// constant member of it invoked. The game profile lists the game's types, so the name is the game's;
// the member starts a program. Expected: Full access, system access "Starts other programs".
using HarmonyLib;

public static class OpenByName {
    public static void Open() => AccessTools.TypeByName("KSA.Links").GetMethod("Open")!.Invoke(null, ["https://example.invalid/"]);
}
