// SPDX-License-Identifier: MIT
// Near miss (D6): the field's declared type is object, which the check does not resolve to the methods of a
// type. Expected: Broad access, "Uses reflection the check cannot trace".
public static class DeclaredTypeObject {
    public static void Go(object target) =>
        typeof(KSA.Universe).GetField("Anything")!.FieldType.GetMethod("Run")!.Invoke(target, ["example.invalid"]);
}
