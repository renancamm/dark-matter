// SPDX-License-Identifier: MIT
// Probe (D9, policy 35): GetType() of a value declared as a game class can be a game type derived from it, whose
// own member of the name looked up starts a program. Expected: Broad access, the bounded reason and "Starts other
// programs" (before: the bounded reason only; the derived type's member was not reached).
public static class DerivedGameMember {
    public static void Go(KSA.Craft craft) => craft.GetType().GetMethod("Launch")?.Invoke(craft, ["example.invalid"]);
}
