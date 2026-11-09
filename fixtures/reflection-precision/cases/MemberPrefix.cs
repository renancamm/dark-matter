// SPDX-License-Identifier: MIT
// GetMember with a name ending in '*' is a prefix lookup: "Copy*" finds UiText.CopyName, which uses
// the clipboard. Expected: Limited access, "Uses your clipboard" (H1a-review H2; before policy 19
// the name was compared as written: no labels). Control: MemberExactName.
using System.Reflection;

public static class MemberPrefix {
    public static void Draw(string text) {
        var ms = typeof(KSA.UiText).GetMember("Copy*", BindingFlags.Public | BindingFlags.Static);
        (ms[0] as MethodInfo)?.Invoke(null, [text]);
    }
}
