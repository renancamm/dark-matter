// SPDX-License-Identifier: MIT
// Probe (H7 review): as ReflectedPathHelper, for a helper that creates a folder and opens it. Opening a folder
// the check cannot place in the mod's or the game's folders counts as starting a program. Expected: Broad
// access, "Starts other programs" (before: Limited access, "Opens its own or the game's folders").
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

internal static class W {
    static void Open(string p) { Directory.CreateDirectory(p); Process.Start(p); }
    internal static void Direct() => Open(Path.Combine(Path.GetDirectoryName(typeof(W).Assembly.Location)!, "logs"));
}

public static class ReflectedFolderHelperEntry {
    public static void Go() {
        W.Direct();
        typeof(W).GetMethod("Open", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "logs")]);
    }
}
