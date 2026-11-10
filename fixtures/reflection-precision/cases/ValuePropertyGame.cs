// SPDX-License-Identifier: MIT
// Probe (D5, policy 35): as ValueFieldGame, through PropertyInfo.GetValue of a game property declared as a game
// class. Expected: Broad access, deep game access only (before: "Uses reflection the check cannot trace").
// Policy 38: reflection bounded to a game type is the label "Uses the game's internals by reflection", not a Broad-access reason.
public static class ValuePropertyGame {
    public static void Go() {
        var focus = typeof(KSA.Universe).GetProperty("Focus")!.GetValue(KSA.Universe.Instance)!;
        focus.GetType().GetMethod("Update")!.Invoke(focus, null);
    }
}
