// SPDX-License-Identifier: MIT
// A prefix lookup ("Ru*") on a trusted library's nested type, found from its outer type: the walker
// counts the nested type as the outer one, which has a harmless Run, while the nested Inner.Run starts a
// program. Expected: Full access, "Starts other programs" (H3 review: the prefix found the outer Run, so
// only that member counted; before policy 19 the name matched no member and the whole type counted).
// Control: TrustedExactName.
using System.Reflection;

public static class TrustedNestedPrefix {
    public static void Go() {
        var inner = typeof(HarmonyLib.NestedHost).GetNestedType("Inner");
        (inner?.GetMember("Ru*", BindingFlags.Public | BindingFlags.Static)[0] as MethodInfo)?.Invoke(null, null);
    }
}
