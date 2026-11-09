// SPDX-License-Identifier: MIT
// Control for MemberPrefix: GetMember with the member's exact name. Expected: Limited access,
// "Uses your clipboard".
using System.Reflection;

public static class MemberExactName {
    public static void Draw(string text) {
        var ms = typeof(KSA.UiText).GetMember("CopyName", BindingFlags.Public | BindingFlags.Static);
        (ms[0] as MethodInfo)?.Invoke(null, [text]);
    }
}
