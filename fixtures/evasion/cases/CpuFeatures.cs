// SPDX-License-Identifier: MIT
// H9 (policy 29): CPU feature checks are a constant per machine: Limited access, nothing labelled (before
// H9: unclassified).
using System.Runtime.Intrinsics.X86;

public static class CpuFeatures {
    public static bool HasAvxFma => Avx.IsSupported && Fma.IsSupported;
}
