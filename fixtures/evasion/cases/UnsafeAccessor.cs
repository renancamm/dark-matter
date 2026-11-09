// SPDX-License-Identifier: MIT
// Probe case: an UnsafeAccessor reaches a private member by name with no reference to it.
// Expected: Broad access.
using System.Runtime.CompilerServices;

public class UnsafeAccessorCase {
    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "ToString")]
    static extern string Call(object o);

    public static string Run(object o) => Call(o);
}
