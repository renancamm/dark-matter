// SPDX-License-Identifier: MIT
// Control for AliasedType: the same reflection on the mod's own harmless type, without the ref local.
// Expected: Limited access, no labels.
using System;

public static class UnaliasedTypeHarmless { public static void Start() { } }

public static class UnaliasedType {
    public static void Run() {
        Type type = null;
        type = typeof(UnaliasedTypeHarmless);
        type.GetMethod("Start", Type.EmptyTypes).Invoke(null, null);
    }
}
