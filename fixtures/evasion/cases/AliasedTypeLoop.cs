// SPDX-License-Identifier: MIT
// Probe case: like AliasedType, but the replaced local is copied and the copy is used inside a loop, where
// the check knows a local only from every value stored to it in the method. What runs is Process.Start.
// Expected: Broad access, "Uses reflection the check cannot trace" (it was Limited access before the H4 review).
using System;

public static class AliasedTypeLoopHarmless { public static void Start() { } }

public static class AliasedTypeLoop {
    public static void Run(int times) {
        Type type = null;
        ref Type alias = ref type;
        type = typeof(AliasedTypeLoopHarmless);
        alias = typeof(System.Diagnostics.Process);
        Type copy = type;
        for (int i = 0; i < times; i++) copy.GetMethod("Start", Type.EmptyTypes).Invoke(null, null);
    }
}
