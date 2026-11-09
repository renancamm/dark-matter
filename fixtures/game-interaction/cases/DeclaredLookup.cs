// SPDX-License-Identifier: MIT
// Control for InheritedLookup: the derived game type's own harmless member, by name. Expected: Limited
// access, no labels.
public static class DeclaredCaller {
    public static void Run(string file) => typeof(KSA.StartsDerived).GetMethod("DeclaredHere")?.Invoke(null, [file]);
}
