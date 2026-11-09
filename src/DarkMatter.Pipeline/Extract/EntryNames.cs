// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;

namespace DarkMatter.Pipeline.Extract;

/// <summary>
/// Archive entry names, checked before anything is written. An entry is refused when it could
/// land outside its folder (absolute path, drive letter, "..") or when its name would not mean the
/// same file on every system a player might extract it on: characters Windows does not allow,
/// names ending in a dot or space (Windows drops them), reserved device names. Refused entries
/// are not written and make the archive count as not extracted.
/// <para>
/// A component named like a version-control, editor or coding-agent folder or file
/// (<see cref="Renamed"/>) is written under a harmless name, <see cref="RenamePrefix"/> plus the
/// name (<c>.git</c> becomes <c>_dm_.git</c>): tools run in or reading an extracted tree would act
/// on them (git takes a <c>.git</c> folder or file as the repository and runs its hooks and
/// configured commands, editors run a folder's tasks when it is opened, coding agents load
/// <c>CLAUDE.md</c> as instructions). Every check applies to the renamed component, and a
/// renamed path that collides with another entry is refused like any collision.
/// </para>
/// </summary>
internal static class EntryNames {
    static readonly string[] Devices = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

    /// <summary>The prefix a <see cref="Renamed"/> component is written with.</summary>
    public const string RenamePrefix = "_dm_";

    /// <summary>
    /// Component names written under <see cref="RenamePrefix"/>, matched ignoring case (dotless i
    /// counts as i, as on NTFS), Unicode normalization and format characters (zero-width and the
    /// like, which some file systems ignore).
    /// </summary>
    public static readonly string[] Renamed = [
        ".git", ".gitmodules", ".gitattributes", ".hg", ".svn", ".bzr", ".jj",  // version control
        ".vscode", ".idea", ".cursor", ".cursorrules",                            // editors
        ".claude", "CLAUDE.md", "CLAUDE.local.md",                                // coding agents
        "AGENTS.md", "AGENTS.override.md", ".gemini", "GEMINI.md",
        ".mcp.json",                                                              // agent tool servers
    ];

    static readonly HashSet<string> RenamedKeys = [.. Renamed.Select(RenameKey)];

    /// <summary>
    /// Splits <paramref name="name"/> into path components ("\" counts as a separator, empty and
    /// "." components are dropped), or returns why it is refused. A directory entry with no
    /// components (the archive's own root, "./") is allowed; a file entry is not. Components named
    /// in <see cref="Renamed"/> come back renamed.
    /// </summary>
    public static string? Check(string name, bool directory, out string[] parts) => Check(name, directory, out parts, out _);

    /// <summary>
    /// <see cref="Check(string, bool, out string[])"/>, and in <paramref name="renamed"/> the
    /// original names of the components that were renamed.
    /// </summary>
    public static string? Check(string name, bool directory, out string[] parts, out string[] renamed) {
        var n = name.Replace('\\', '/');
        var original = n.Split('/').Where(p => p.Length > 0 && p != ".").ToArray();
        renamed = [.. original.Where(IsRenamed)];
        parts = [.. original.Select(p => IsRenamed(p) ? RenamePrefix + p : p)];
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

    /// <summary>
    /// Whether <paramref name="name"/> is usable as one folder name as it is: one component that
    /// passes every check and is not renamed (for listing ids, which name folders in the state).
    /// </summary>
    public static bool IsFolderName(string name) =>
        Check(name, directory: true, out var parts) == null && parts.Length == 1 && parts[0] == name;

    static bool IsRenamed(string part) => Normalizable(part) && RenamedKeys.Contains(RenameKey(part));

    // Dotless i is matched as i: NTFS upper-cases it to I (".gıt" opens ".git" on Windows), while
    // ToUpperInvariant leaves it as it is. Long s already upper-cases to S.
    static string RenameKey(string part) =>
        Key(new string([.. part.Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.Format).Select(c => c == 'ı' ? 'i' : c)]));

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
