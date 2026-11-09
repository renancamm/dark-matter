// SPDX-License-Identifier: MIT
// The same cached filter given to Where, then First(): a filtering Where is not a name filter even
// with a delegate made where it is used, so the lookup reaches every member of the type, the clipboard
// one included. Expected: as CachedNameFilter, Limited access and "Uses your clipboard" (Broad access,
// deep game access, before policy 23).
using System.Linq;
using System.Reflection;

public static class CachedWhereDrawer {
    public static void Draw(string text) {
        var draw = typeof(KSA.UiText).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.Name == "Draw").First();
        draw.Invoke(null, [text]);
    }
}
