// SPDX-License-Identifier: MIT
// Probe (H7 review): a private file-writing helper that reflection reaches by its name is given any path.
// Its one direct call writes into the mod's own folder; the reflective call passes a path in the user's
// profile. Expected: Limited access, "Changes files in its own or the game's folders" and "Changes files
// outside the game" (before: only the first).
using System;
using System.IO;
using System.Reflection;

internal static class W {
    static void Write(string p) => File.WriteAllText(p, "");
    internal static void Direct() => Write(Path.Combine(Path.GetDirectoryName(typeof(W).Assembly.Location)!, "settings.txt"));
}

public static class ReflectedPathHelperEntry {
    public static void Go() {
        W.Direct();
        typeof(W).GetMethod("Write", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "settings.txt")]);
    }
}
