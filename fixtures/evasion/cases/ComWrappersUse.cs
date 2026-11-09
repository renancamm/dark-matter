// SPDX-License-Identifier: MIT
// H9 (policy 29): the COM source generator's wrappers reach native COM objects: native code (as
// ComWrappers already is; before H9: unclassified).
using System.Runtime.InteropServices.Marshalling;

public static class ComWrappersUse {
    public static object Make() => new StrategyBasedComWrappers();
}
