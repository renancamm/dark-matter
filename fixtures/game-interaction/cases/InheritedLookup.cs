// SPDX-License-Identifier: MIT
// A game member found by name through a derived game type: GetMethod searches the base types, so this
// runs KSA.StartsBase.InheritedRun, which starts what it is given (H5 review). Expected: Broad access,
// "Starts other programs".
public static class InheritedStarter {
    public static void Run(string file) => typeof(KSA.StartsDerived).GetMethod("InheritedRun")?.Invoke(null, [file]);
}
