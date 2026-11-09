// SPDX-License-Identifier: MIT
// Control for TypeNameIgnoreCase: the same lookup with ignoreCase false and the type's own name.
// Expected: Full access, "Starts other programs".
public static class TypeNameExactCase {
    public static void Go() =>
        System.Type.GetType("KSA.Tools+Shell, KSA", false, false)?.GetMethod("Run")?.Invoke(null, ["example.invalid"]);
}
