// SPDX-License-Identifier: MIT
// Probe (D3, D9, policy 35): GetType() of a value declared as a game interface is a type implementing it; the
// game's implementer saves the game. Expected: Full access, deep game access only, "Changes game saves" (before:
// nothing labelled).
public static class DerivedGameInterface {
    public static void Go(KSA.IPayload payload) => payload.GetType().GetMethod("Deploy")!.Invoke(payload, null);
}
