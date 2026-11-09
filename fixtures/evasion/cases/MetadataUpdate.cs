// SPDX-License-Identifier: MIT
// Hot reload: MetadataUpdater.ApplyUpdate replaces the IL of a loaded assembly's methods with what
// the deltas hold, which the check never sees. Here the deltas are empty.
// Expected: Full access, "Builds code at run time".
using System;
using System.Reflection.Metadata;

public static class MetadataUpdate {
    public static void Apply() =>
        MetadataUpdater.ApplyUpdate(typeof(MetadataUpdate).Assembly, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
}
