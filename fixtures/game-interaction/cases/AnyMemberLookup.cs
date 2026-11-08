// SPDX-License-Identifier: MIT
// The rule next to NamedMemberLookup: the same lookup with a filter that does not name the member
// reaches every member of the type, the clipboard one included. Expected: Known access, "Uses your
// clipboard".
using System.Linq;
using System.Reflection;

public static class AnyDrawer {
    public static void Draw(string text, int arity) {
        var draw = typeof(KSA.UiText).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .FirstOrDefault(m => m.GetParameters().Length == arity);
        draw?.Invoke(null, [text]);
    }
}
