// SPDX-License-Identifier: MIT
// Control (policy 39): a pointer local that holds a pointer the game returned on one path and one made from a
// number on the other. Expected: Broad access, deep game access.
public static unsafe class GamePointerMixedLocal {
    public static void Use(bool own, nint address) {
        KSA.Viewport* viewport = own ? KSA.Ui.GetMainViewport() : (KSA.Viewport*)address;
        KSA.Ui.Use(viewport);
    }
}
