// SPDX-License-Identifier: MIT
// Probe (H7b): as StaticAbstractExplicit, implemented implicitly by a public static method of an internal type,
// and by one a type inherits from its base class (the compiler adds a forwarding method). Expected: Broad
// access, "Uses reflection the check cannot trace" (before: Limited access, nothing).
using System;

internal interface IStaticRunImplicit { static abstract void Run(Type t); }

internal sealed class StaticRunImplicit : IStaticRunImplicit {
    public static void Run(Type t) => t.GetMethod("Open")?.Invoke(null, ["example.invalid"]);
}

internal class StaticRunBase {
    public static void Run(Type t) => t.GetMethod("Open")?.Invoke(null, ["example.invalid"]);
}

internal sealed class StaticRunInherited : StaticRunBase, IStaticRunImplicit { }

public static class StaticAbstractImplicitEntry {
    static void Call<T>(Type t) where T : IStaticRunImplicit => T.Run(t);
    public static void Go() {
        Call<StaticRunImplicit>(typeof(KSA.Links));
        Call<StaticRunInherited>(typeof(KSA.Links));
    }
}
