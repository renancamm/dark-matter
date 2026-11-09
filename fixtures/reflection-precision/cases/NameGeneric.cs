// SPDX-License-Identifier: MIT
// A member name given to a method of the mod's own generic type (a call through a member
// reference on Helper<int>), which looks a game method up by that name and invokes it. The name
// comes from the console. Expected: Broad access, "Starts other programs" (any member of KSA.Links
// can be reached; G1a review A10).
using System;

internal static class Helper<T> {
    internal static void Run(string name) => typeof(KSA.Links).GetMethod(name).Invoke(null, new object[] { "example.invalid" });
}

public static class NameGeneric {
    public static void Go() => Helper<int>.Run(Console.ReadLine());
}
