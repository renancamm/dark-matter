// SPDX-License-Identifier: MIT
// A private method of the mod reached by Delegate.CreateDelegate(Type, Type, string), called with a
// Type argument no direct caller passes: its own reflection on that parameter cannot be traced.
// Expected: Full access, "Uses reflection the check cannot trace" (H1a-review XF1Delegate; before
// policy 19, Limited access, no labels).
using System;

internal static class DelegateTarget {
    private static void Run(Type t, string text) => t.GetMethod("CopyName")?.Invoke(null, [text]);
}

public static class DelegateByNameOwn {
    public static void Go(string text) =>
        ((Action<Type, string>)Delegate.CreateDelegate(typeof(Action<Type, string>), typeof(DelegateTarget), "Run"))(typeof(KSA.UiText), text);
}
