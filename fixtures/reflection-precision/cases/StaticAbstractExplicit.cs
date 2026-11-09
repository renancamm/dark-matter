// SPDX-License-Identifier: MIT
// Probe (H7 review, H7b): a static abstract interface member (C# 11) implemented explicitly by a private static
// method, called through a constrained call on a type parameter (T.Run(t)), which names the interface member.
// The implementation's argument can be any type. Expected: Broad access, "Uses reflection the check cannot
// trace" (before: Limited access, nothing: it was traced from its direct calls, of which there are none).
using System;

internal interface IStaticRun { static abstract void Run(Type t); }

internal sealed class StaticRunExplicit : IStaticRun {
    static void IStaticRun.Run(Type t) => t.GetMethod("Open")?.Invoke(null, ["example.invalid"]);
}

public static class StaticAbstractExplicitEntry {
    static void Call<T>(Type t) where T : IStaticRun => T.Run(t);
    public static void Go() => Call<StaticRunExplicit>(typeof(KSA.Links));
}
