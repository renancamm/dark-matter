// SPDX-License-Identifier: MIT
// Control: a game method found by an assembly-qualified type name and a constant method name, then
// invoked. With the game profile, the mod gets what that game member does (it saves the game).
// Expected: Limited access, "Changes game saves" only.
using System;

public static class SaveByName {
    public static void Save() => Type.GetType("KSA.GameSaves, KSA", true)!.GetMethod("MakeSave")!.Invoke(null, null);
}
