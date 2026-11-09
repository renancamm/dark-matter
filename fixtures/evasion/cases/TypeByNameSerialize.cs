// SPDX-License-Identifier: MIT
// H9 negative: the type found by name is handed to a serializer, which creates it and runs its setters:
// still "Calls code that was not analyzed".
using System.Text.Json;
using HarmonyLib;

public static class TypeByNameSerialize {
    public static object? Load(string json) => JsonSerializer.Deserialize(json, AccessTools.TypeByName("OtherMod.Settings"));
}
