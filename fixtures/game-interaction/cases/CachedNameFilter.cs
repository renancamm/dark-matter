// SPDX-License-Identifier: MIT
// NamedMemberLookup's filter without the capture: m => m.Name == "Draw" captures nothing, so the
// compiler caches the delegate in a static field of <>c and FirstOrDefault is given that field's
// value, not a delegate made where it is used. The name-filter proof does not follow the field, so the
// lookup reaches every member of the type, the clipboard one included (docs/known-gaps.md, "Name
// filters"). The control is NamedMemberLookup (a capturing filter, proved). Expected: Limited access and
// "Uses your clipboard", as AnyMemberLookup. Before policy 23 (H7) also Broad access, deep game access
// (bounded reflection): the array was lost at the join after the cache's null check.
using System.Linq;
using System.Reflection;

public static class CachedDrawer {
    public static void Draw(string text) {
        var draw = typeof(KSA.UiText).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .FirstOrDefault(m => m.Name == "Draw");
        draw?.Invoke(null, [text]);
    }
}
