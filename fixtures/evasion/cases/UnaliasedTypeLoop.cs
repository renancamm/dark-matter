// SPDX-License-Identifier: MIT
// Control for AliasedTypeLoop: the same copy and loop on the mod's own harmless type, without the ref local.
// Expected: Limited access, no labels.
using System;

public static class UnaliasedTypeLoopHarmless { public static void Start() { } }

public static class UnaliasedTypeLoop {
    public static void Run(int times) {
        Type type = null;
        type = typeof(UnaliasedTypeLoopHarmless);
        Type copy = type;
        for (int i = 0; i < times; i++) copy.GetMethod("Start", Type.EmptyTypes).Invoke(null, null);
    }
}
