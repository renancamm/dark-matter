// SPDX-License-Identifier: MIT
// AccessTools.MakeDeepCopy<T> for a game type: it creates an instance and sets its members, here the
// game options type whose AutoSave setter saves the game. Expected: Limited access, "Changes game
// saves" (G5a).
using HarmonyLib;

public static class Copier {
    public static KSA.VesselOptions Copy(object source) => AccessTools.MakeDeepCopy<KSA.VesselOptions>(source);
}
