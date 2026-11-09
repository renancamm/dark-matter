// SPDX-License-Identifier: MIT
// A game type's method array given a method the check cannot trace through Array.SetValue (a
// framework member that writes into it), then an element invoked. Expected: Full access, "Uses
// reflection the check cannot trace", not only the bounded reason (G1a review A9).
using System;

public static class Src { public static Action Hook; }

public static class LookupSetValue {
    public static void Go() {
        var methods = typeof(KSA.Tools).GetMethods();
        methods.SetValue(Src.Hook.Method, 0);
        methods[0].Invoke(null, null);
    }
}
