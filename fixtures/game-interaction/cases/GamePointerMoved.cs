// SPDX-License-Identifier: MIT
// Control (policy 39): arithmetic on a pointer the game returned gives an address the game did not hand out.
// Expected: Broad access, deep game access, "Reads or writes memory directly".
public static unsafe class GamePointerMoved {
    public static void Next() => KSA.Ui.Use(KSA.Ui.GetMainViewport() + 1);
}
