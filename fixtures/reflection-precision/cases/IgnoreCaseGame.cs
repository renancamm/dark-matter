// SPDX-License-Identifier: MIT
// A game method that starts a program, looked up with BindingFlags.IgnoreCase under another
// spelling ("run" for Shell.Run) and invoked. The lookup finds Run all the same. Expected: Broad
// access, "Starts other programs" (H1a-review H1; before policy 19 the check compared the name
// exactly and found nothing: Limited access, no labels). Control: ExactNameGame.
using System.Reflection;

public static class IgnoreCaseGame {
    public static void Go() =>
        typeof(KSA.Tools).GetNestedType("Shell")?.GetMethod("run", BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase)?.Invoke(null, ["example.invalid"]);
}
