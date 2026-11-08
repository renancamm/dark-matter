// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace DarkMatter.Pipeline;

/// <summary>Output helpers shared by the commands.</summary>
internal static class Text {
    /// <summary>
    /// <paramref name="s"/> in quotes with control and format characters escaped, for printing
    /// names that come from archives, listings or releases: they must not be able to move the
    /// cursor or rewrite earlier lines in a terminal.
    /// </summary>
    public static string Quote(string s) => Escape(s, quoted: true);

    /// <summary><paramref name="s"/> with control and format characters escaped, unquoted.</summary>
    public static string Printable(string s) => Escape(s, quoted: false);

    static string Escape(string s, bool quoted) {
        var b = new StringBuilder(quoted ? "'" : "");
        foreach (var c in s) {
            if (quoted && c is '\'' or '\\') b.Append('\\').Append(c);
            else if (char.IsControl(c) || CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
                b.Append(CultureInfo.InvariantCulture, $"\\u{(int)c:x4}");
            else b.Append(c);
        }
        return (quoted ? b.Append('\'') : b).ToString();
    }

    public static readonly JsonSerializerOptions Json = new() {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // Paths and names are written as they are (non-ASCII escaped, as Python's json module does).
        Encoder = JavaScriptEncoder.Default,
    };

    /// <summary>Writes <paramref name="value"/> as indented JSON, through a temporary file so a failed run leaves no half-written output.</summary>
    public static void WriteJson(string path, object value) {
        var tmp = path + ".part";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, Json) + "\n");
        File.Move(tmp, path, overwrite: true);
    }
}
