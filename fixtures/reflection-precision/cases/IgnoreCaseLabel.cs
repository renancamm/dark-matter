// SPDX-License-Identifier: MIT
// A game member that uses the clipboard, looked up with BindingFlags.IgnoreCase under another
// spelling ("copyname" for UiText.CopyName). Expected: Limited access, "Uses your clipboard"
// (H1a-review H1; before policy 19, no labels).
using System.Reflection;

public static class IgnoreCaseDrawer {
    public static void Draw(string text) {
        var m = typeof(KSA.UiText).GetMethod("copyname", BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase);
        m?.Invoke(null, [text]);
    }
}
