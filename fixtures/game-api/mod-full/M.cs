// SPDX-License-Identifier: MIT
// Hands a game wrapper a target to start: Full access through the game-API map.
namespace GameApiModFull {
    public class Mod {
        public void Open(string target) => KSA.Links.Open(target);
        // foreach over a game inline array (C5 near-miss): the compiler's InlineArrayElementRef<KSA.Slots7, int>(ref s, i)
        // with the loop variable as the index, which the check cannot bound, stays raw memory (README, Known gaps).
        public int Sum() { var s = new KSA.Slots7(); int sum = 0; foreach (var x in s) sum += x; return sum; }
    }
}
