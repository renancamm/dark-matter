// SPDX-License-Identifier: MIT
// Control (H7b): a static abstract interface member's implementation that does nothing with its argument:
// any argument changes nothing. Expected: Limited access, no labels.
using System;

internal interface IStaticMake { static abstract int Make(Type t); }

internal sealed class StaticMakeBenign : IStaticMake {
    public static int Make(Type t) => 1;
}

public static class StaticAbstractBenignEntry {
    static int Call<T>(Type t) where T : IStaticMake => T.Make(t);
    public static int Go() => Call<StaticMakeBenign>(typeof(KSA.Links));
}
