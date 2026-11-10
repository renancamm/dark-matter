// SPDX-License-Identifier: MIT
// Control (policy 39): a pointer the game returned, read as another type than it points to (a pointer cast
// leaves no instruction behind). Expected: Broad access, deep game access.
public static unsafe class GamePointerOtherType {
    public static int Width() => ((KSA.Panel*)KSA.Ui.GetMainViewport())->Width;
}
