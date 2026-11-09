// SPDX-License-Identifier: MIT
// Calls the game API only; what it does is known through the game-API capability map.
namespace GameApiMod {
    public class Mod {
        public void Tick() => KSA.GameSaves.MakeSave();
        // A span over a game inline array (C5): the compiler's InlineArrayAsSpan<KSA.Slots7, int>(ref s, 7),
        // checked against the length the game-API map records. Limited access.
        public int Slots() { var s = new KSA.Slots7(); System.Span<int> span = s; return span.Length; }
    }
}
