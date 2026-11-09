// SPDX-License-Identifier: MIT
// Probe case: a local holding a harmless type is replaced through a ref local taken before the type was
// stored, then a method of "it" is invoked by name. What runs is Process.Start, not the harmless method.
// Expected: Broad access, "Uses reflection the check cannot trace" (it was Limited access before policy 20).
using System;

public static class AliasedTypeHarmless { public static void Start() { } }

public static class AliasedType {
    public static void Run() {
        Type type = null;
        ref Type alias = ref type;
        type = typeof(AliasedTypeHarmless);
        alias = typeof(System.Diagnostics.Process);
        type.GetMethod("Start", Type.EmptyTypes).Invoke(null, null);
    }
}
