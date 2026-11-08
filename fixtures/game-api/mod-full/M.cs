// SPDX-License-Identifier: MIT
// Hands a game wrapper a target to start: Full access through the game-API map.
namespace GameApiModFull {
    public class Mod {
        public void Open(string target) => KSA.Links.Open(target);
    }
}
