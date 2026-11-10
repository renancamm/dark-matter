// SPDX-License-Identifier: MIT
// Probe (D3, D9, policy 35): GetType() of a value declared as a game interface is a type implementing it; the
// game's implementer saves the game. Expected: Broad access, deep game access only, "Changes game saves" (before:
// nothing labelled).
// Policy 38: reflection bounded to a game type is the label "Uses the game's internals by reflection", not a Broad-access reason.
public static class DerivedGameInterface {
    public static void Go(KSA.IPayload payload) => payload.GetType().GetMethod("Deploy")!.Invoke(payload, null);
}
