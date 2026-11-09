// SPDX-License-Identifier: MIT
// Probe (D6, policy 35): FieldInfo.FieldType of a game field found by a constant name on exactly a game type is
// exactly its declared type, so a method looked up on it by a constant name is that method. Expected: Limited
// access, nothing labelled (before: "Uses reflection the check cannot trace").
public static class DeclaredFieldType {
    public static void Go() {
        var console = typeof(KSA.Universe).GetField("Console")!;
        console.FieldType.GetMethod("Print")!.Invoke(console.GetValue(KSA.Universe.Instance), ["hello"]);
    }
}
