// SPDX-License-Identifier: MIT
// A game type found by name ignoring case (Type.GetType(name, throwOnError, ignoreCase: true)):
// the name the check reads is not the type's. Expected: Broad access, "Uses reflection the check
// cannot trace" (before policy 19 the lowercase name matched no game type: Limited access, no
// labels). Control: TypeNameExactCase.
public static class TypeNameIgnoreCase {
    public static void Go() =>
        System.Type.GetType("ksa.tools+shell, KSA", false, true)?.GetMethod("Run")?.Invoke(null, ["example.invalid"]);
}
