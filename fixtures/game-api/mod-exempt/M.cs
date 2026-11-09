// SPDX-License-Identifier: MIT
// Calls game members whose Broad-access capabilities the policy exempts: the game's own raw
// memory use (no label), and its browser opener (labelled as opening websites).
namespace GameApiModExempt {
    public class Mod {
        public float Length(KSA.Vec3 v) => v.First();
        public void Help() => KSA.UpdateAvailablePopup.OpenBrowser("https://example.invalid/help");
    }
}
