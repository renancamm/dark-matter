// SPDX-License-Identifier: MIT
// Negative for the H7 stack join (J1): two different member arrays meet on the stack at the join after
// the conditional. The walker keeps a collection across a block start only when every way in carries
// the same one there; here the entry holds neither, so the element invoked is not traced. Expected
// (before and after H7): Broad access, "Uses reflection the check cannot trace", and "Uses your clipboard".
// (H1a-review probe XG5cJoin.)
using System.Linq;

public static class JoinDrawer {
    public static void Draw(string text, bool b) {
        var draw = (b ? typeof(KSA.UiText).GetMethods() : typeof(KSA.Native).GetMethods())
            .FirstOrDefault(m => m.GetParameters().Length == 1);
        draw?.Invoke(null, [text]);
    }
}
