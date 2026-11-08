// SPDX-License-Identifier: MIT
// References no network API itself; the capability arrives through the helper library.
namespace PropagationMod {
    public class Mod {
        public string Run() => NetHelper.Downloader.Fetch("https://example.invalid/data");
    }
}
