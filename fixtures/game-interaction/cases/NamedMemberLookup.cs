// SPDX-License-Identifier: MIT
// Control: a member taken from a game type's GetMethods() by a lambda that requires its name to be a
// constant ("Draw"). Only that member is reached, not KSA.UiText's clipboard method. Expected: Known
// access, no labels.
using System.Linq;
using System.Reflection;

public static class TextDrawer {
    public static void Draw(string text, int arity) {
        var draw = typeof(KSA.UiText).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .FirstOrDefault(m => m.Name == "Draw" && m.GetParameters().Length == arity);
        draw?.Invoke(null, [text]);
    }
}
