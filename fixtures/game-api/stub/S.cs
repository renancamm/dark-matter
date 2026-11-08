// SPDX-License-Identifier: MIT
// Stand-in for a game assembly: a public API method that writes to the save folder, a wrapper
// that starts whatever its caller names (Full access for the mod that calls it), a math type
// that reads its own memory (exempt by the policy's "KSA." entry), a browser opener (exempt
// as "opens websites" by the policy), and types mods use through reflection (one member of UiText
// uses the clipboard).
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace KSA {
    public static class GameSaves {
        public static string SaveFolderPath => "saves";
        public static void MakeSave() => System.IO.File.WriteAllText(System.IO.Path.Combine(SaveFolderPath, "save.dat"), "");
    }

    public static class Links {
        public static void Open(string target) => Process.Start(target);
    }

    public static class UpdateAvailablePopup {
        public static void OpenBrowser(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    // Options a mod reads by reflection: one setter saves the game.
    public class VesselOptions {
        public int Throttle { get; set; }
        public bool AutoSave { get => true; set { if (value) GameSaves.MakeSave(); } }
    }

    // A game object with a private field a mod reads, and a method a mod patches.
    public class Vehicle {
        float mass = 1;
        public float Mass => mass;
        public void Update() { }
    }

    // A UI type a mod reaches by reflection: one member copies to the clipboard, the other draws text.
    public static class UiText {
        public static void Draw(string text) { }
        public static void CopyName(string text) => Native.SetClipboardText(text);
    }

    public static class Native {
        public static void SetClipboardText(string text) { }
    }

    public struct Vec3 {
        public float X, Y, Z;
        public float First() => Unsafe.As<Vec3, float>(ref this);
    }
}
