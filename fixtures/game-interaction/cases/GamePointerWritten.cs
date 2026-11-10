// SPDX-License-Identifier: MIT
// Control (policy 39): a write through a pointer the game returned. Expected: Broad access, deep game access,
// "Reads or writes memory directly".
public static unsafe class GamePointerWritten {
    public static void Rename() {
        KSA.Viewport* viewport = KSA.Ui.GetMainViewport();
        viewport->Id = 1;
    }
}
