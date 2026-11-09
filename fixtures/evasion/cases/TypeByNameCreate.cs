// SPDX-License-Identifier: MIT
// H9 negative: the type found by name is created, which runs its code: still "Calls code that was not analyzed".
using System;
using HarmonyLib;

public static class TypeByNameCreate {
    public static object? Make() => AccessTools.TypeByName("OtherMod.Feature") is { } t ? Activator.CreateInstance(t) : null;
}
