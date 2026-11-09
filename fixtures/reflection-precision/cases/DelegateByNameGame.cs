// SPDX-License-Identifier: MIT
// A game method reached by Delegate.CreateDelegate(Type, Type, string): a lookup by name on the
// type given. Expected: Broad access, "Starts other programs" (H1a-review H3; before policy 19 the
// check only required the type to be traced: Limited access, no labels). Control: ExactNameGame.
using System;

public static class DelegateByNameGame {
    public static void Go() => ((Action<string>)Delegate.CreateDelegate(typeof(Action<string>), typeof(KSA.Tools.Shell), "Run"))("example.invalid");
}
