// SPDX-License-Identifier: MIT
// Delegate.CreateDelegate(Type, Type, string, ignoreCase: true, throwOnBindFailure) under another
// spelling. Expected: Full access, "Starts other programs" (H1 and H3).
using System;

public static class DelegateByNameIgnoreCase {
    public static void Go() => ((Action<string>)Delegate.CreateDelegate(typeof(Action<string>), typeof(KSA.Tools.Shell), "rUN", true, true)!)("example.invalid");
}
