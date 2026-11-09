// SPDX-License-Identifier: MIT
// H9 (policy 29): GCHandle.Alloc (pinning or keeping an object alive) and IsAllocated touch no memory:
// Limited access, nothing labelled (before H9: unclassified). Free, Target and FromIntPtr are raw memory
// (GCHandleForged).
using System.Runtime.InteropServices;

public static class GCHandleAlloc {
    static GCHandle kept;
    public static bool Keep(object o) {
        kept = GCHandle.Alloc(o);
        var pinned = GCHandle.Alloc(new byte[4], GCHandleType.Pinned);
        return kept.IsAllocated && pinned.IsAllocated && kept != pinned;
    }
}
