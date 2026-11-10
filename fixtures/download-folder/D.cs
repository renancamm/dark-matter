// SPDX-License-Identifier: MIT
// Control (policy 41): connects to the internet, and in its own folder only makes a folder and deletes a
// file. Neither puts content where the loader looks, so the pair is not "Connects to the internet and
// changes files where the game loads code from". Expected: Limited access, with both labels.
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

public class Checker {
    static string ModFolder => Path.GetDirectoryName(typeof(Checker).Assembly.Location);

    public static async Task<string> Check() {
        Directory.CreateDirectory(Path.Combine(ModFolder, "cache"));
        File.Delete(Path.Combine(ModFolder, "cache", "stale.txt"));
        return await new HttpClient().GetStringAsync("https://example.invalid/version.txt");
    }
}
