// SPDX-License-Identifier: MIT
// Calls the game API only; what it does is known through the game-API capability map.
namespace GameApiMod {
    public class Mod {
        public void Tick() => KSA.GameSaves.MakeSave();
    }
}
