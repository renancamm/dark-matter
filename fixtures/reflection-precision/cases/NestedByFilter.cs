// SPDX-License-Identifier: MIT
// The same nested type found with GetMembers() and a filter that requires its name. Expected: Broad
// access, "Starts other programs" (G1a review A8).
using System;
using System.Linq;

public static class NestedByFilter {
    public static void Go(string tag) {
        var shell = (Type)typeof(KSA.Tools).GetMembers().First(m => m.Name == "Shell" && tag != null);
        shell.GetMethod("Run").Invoke(null, new object[] { "example.invalid" });
    }
}
