// SPDX-License-Identifier: MIT
using System.Text;

namespace DarkMatter.Pipeline.Extract;

/// <summary>
/// Archive entry names, checked before anything is written. An entry is refused when it could
/// land outside its folder (absolute path, drive letter, "..") or when its name would not mean the
/// same file on every system a player might extract it on: characters Windows does not allow,
/// names ending in a dot or space (Windows drops them), reserved device names. Refused entries
/// are not written and make the archive count as not extracted.
/// </summary>
internal static class EntryNames {
    static readonly string[] Devices = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

    /// <summary>
    /// Splits <paramref name="name"/> into path components ("\" counts as a separator, empty and
    /// "." components are dropped), or returns why it is refused. A directory entry with no
    /// components (the archive's own root, "./") is allowed; a file entry is not.
    /// </summary>
    public static string? Check(string name, bool directory, out string[] parts) {
        var n = name.Replace('\\', '/');
        parts = [.. n.Split('/').Where(p => p.Length > 0 && p != ".")];
        if (n.StartsWith('/')) return "absolute path";
        if (parts.Length == 0) return directory ? null : "empty name";
        foreach (var p in parts) {
            if (p == "..") return "'..' component";
            if (p.Any(c => char.IsControl(c) || c is '<' or '>' or ':' or '"' or '|' or '?' or '*')) return "character not allowed in a file name";
            if (p.EndsWith('.') || p.EndsWith(' ')) return "name ends in a dot or space";
            var stem = p.Split('.')[0].TrimEnd(' ');
            if (Devices.Contains(stem, StringComparer.OrdinalIgnoreCase) || IsNumberedDevice(stem)) return "reserved device name";
            if (!Normalizable(p)) return "invalid Unicode in name";
        }
        return null;
    }

    static bool IsNumberedDevice(string s) =>
        s.Length == 4 && (s.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || s.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && s[3] is >= '1' and <= '9';

    static bool Normalizable(string s) {
        try {
            _ = s.Normalize(NormalizationForm.FormC);
            return true;
        } catch (ArgumentException) {
            return false;
        }
    }

    /// <summary>
    /// The key two names collide on: the same letters ignoring case and Unicode normalization, as
    /// on the default file systems of Windows and macOS. Two entries with one key would be one
    /// file there, and which one wins depends on the tool that extracts them.
    /// </summary>
    public static string Key(string part) => part.Normalize(NormalizationForm.FormC).ToUpperInvariant();
}
