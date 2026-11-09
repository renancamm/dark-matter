// SPDX-License-Identifier: MIT
// A game method taken as a delegate (ldftn) and called through it: the game method starts whatever
// its caller names. Expected: Full access, "Starts other programs" from the game-API map (G5a).
using System;

public static class Opener {
    public static void Go(string target) {
        Action<string> open = KSA.Links.Open;
        open(target);
    }
}
