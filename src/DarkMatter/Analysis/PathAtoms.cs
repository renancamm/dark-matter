// SPDX-License-Identifier: MIT
using System.Text.RegularExpressions;

namespace DarkMatter.Analysis;

/// <summary>
/// Where a file path comes from, as a set of atoms (see <see cref="FileOp"/>). The walker builds
/// the atoms of each path value from the sources, literals, arguments, fields and calls it is made
/// of; the Evaluator resolves the reference atoms across the mod.
/// </summary>
internal static partial class PathAtoms {
    public const string Untraced = "untraced";
    public const string Absolute = "absolute";
    public const string Url = "url";
    /// <summary>
    /// Where the path begins is not traced: an untraced value, a literal that is not rooted, or an edit
    /// that can drop the beginning. Such a path can be a web address even when its traced parts are
    /// folders. Not an origin: it only decides whether a file operation that also takes a web address
    /// (<see cref="FileOp.Url"/>) can connect to the internet.
    /// </summary>
    public const string Head = "head";
    /// <summary>
    /// How the path ends is not traced to a name without an extension: the last part is a literal with
    /// a dot, a value the check cannot follow, a source path (a mod's or the game's folder can be named
    /// "x.app"), or an edit of the end. Opening such a folder with the shell can open a bundle or a shell
    /// folder rather than a plain folder. Not an origin: it only decides <see cref="FolderOpen"/>.
    /// </summary>
    public const string End = "end";
    // A reference appended to a path ("tail:arg:..."): its origins count, where it begins does not.
    const string TailPrefix = "tail:";
    // A reference followed by more of the path ("mid:arg:..."): its origins count, how it ends does not.
    const string MidPrefix = "mid:";
    // A literal naming the game's folder ("My Games", "Kitten Space Agency"). It never survives a
    // combination: the Documents or environment origins combined with it become the game's folder.
    const string GameLiteral = "gamelit";
    const char Separator = '\u001f';

    /// <summary>Types whose values carry a file path: strings, and file-system objects made from one.</summary>
    public static bool IsPathType(string type) => type is "System.String" or "System.String[]"
        or "System.IO.FileInfo" or "System.IO.DirectoryInfo" or "System.IO.FileSystemInfo"
        or "System.IO.FileInfo[]" or "System.IO.DirectoryInfo[]" or "System.IO.FileSystemInfo[]" or "System.IO.FileSystemWatcher";

    /// <summary>File-system objects whose instance members act on the path they were made from.</summary>
    public static bool IsFileSystemObject(string type) => type is "System.IO.FileInfo" or "System.IO.DirectoryInfo"
        or "System.IO.FileSystemInfo" or "System.IO.FileSystemWatcher";

    // A ".." path segment: a literal with one can leave whatever folder it is combined with.
    [GeneratedRegex(@"(^|[\\/])\.\.([\\/]|$)")]
    private static partial Regex Traversal();

    /// <summary>The atoms of a string literal. <paramref name="whole"/>: the literal starts a path
    /// (it is the whole path, or an operand of Path.Combine, where a rooted operand replaces what
    /// came before), so a rooted literal is an absolute path; a literal appended to a path is not.</summary>
    public static IEnumerable<string> OfLiteral(string s, bool whole, Policy policy) {
        // A web address (any scheme but file:, which is a path).
        if (whole && s.Contains("://", StringComparison.Ordinal) && !s.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) yield return Url;
        else if (whole && policy.AbsolutePathLiteral.IsMatch(s)) yield return Absolute;
        if (Traversal().IsMatch(s)) yield return Untraced;
        if (policy.GameFolderLiteral.IsMatch(s)) yield return GameLiteral;
    }

    /// <summary>
    /// A literal that, beginning a path, does not fix where the path begins as a folder: not rooted
    /// (an empty or relative literal, or "http", can be followed by "://...") and not a web address
    /// (which is <see cref="Url"/>).
    /// </summary>
    public static bool LooseStart(string s, Policy policy) =>
        !(s.Contains("://", StringComparison.Ordinal) && !s.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) && !policy.AbsolutePathLiteral.IsMatch(s);

    /// <summary>
    /// A literal that, ending a path, does not fix it as a plain folder name: its last name (after any
    /// trailing separator) has a dot, or there is none (the end is whatever came before).
    /// </summary>
    public static bool LooseEnd(string s) {
        var name = s.TrimEnd('/', '\\');
        name = name[(name.LastIndexOfAny(['/', '\\']) + 1)..];
        return name.Length == 0 || name.Contains('.', StringComparison.Ordinal);
    }

    /// <summary>The atoms of a value appended to a path: where it begins does not matter there.</summary>
    public static IEnumerable<string> Tail(IEnumerable<string> atoms) =>
        atoms.Where(a => a != Head).Select(a => IsReference(a) && !a.StartsWith(TailPrefix, StringComparison.Ordinal) ? TailPrefix + a : a);

    /// <summary>The atoms of a value followed by more of the path: how it ends does not matter there.</summary>
    public static IEnumerable<string> Mid(IEnumerable<string> atoms) =>
        atoms.Where(a => a != End).Select(a => IsReference(a) && !a.StartsWith(MidPrefix, StringComparison.Ordinal) ? MidPrefix + a : a);

    /// <summary>Whether an atom refers to other values (resolved across the mod) rather than being an origin.</summary>
    public static bool IsReference(string a) => a.StartsWith("arg:", StringComparison.Ordinal) || a.StartsWith("field:", StringComparison.Ordinal)
        || a.StartsWith("ret:", StringComparison.Ordinal) || a.StartsWith("game:", StringComparison.Ordinal) || a.StartsWith(TailPrefix, StringComparison.Ordinal)
        || a.StartsWith(MidPrefix, StringComparison.Ordinal);

    /// <summary>
    /// For a reference appended to a path or followed by more of it: the reference itself, and the
    /// marker (<see cref="Head"/> or <see cref="End"/>) that does not apply there; null for any other atom.
    /// </summary>
    public static (string Reference, string Drops)? Positioned(string a) =>
        a.StartsWith(TailPrefix, StringComparison.Ordinal) ? (a[TailPrefix.Length..], Head)
        : a.StartsWith(MidPrefix, StringComparison.Ordinal) ? (a[MidPrefix.Length..], End)
        : null;

    public static string Encode(IEnumerable<string> atoms) => string.Join(Separator, atoms.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));

    public static IEnumerable<string> Decode(string? text) =>
        string.IsNullOrEmpty(text) ? [] : text.Split(Separator);

    public static string Argument(string methodKey, int index) => $"arg:{methodKey}#{index}";
    public static string Field(string fieldKey) => "field:" + fieldKey;
    public static string Return(string methodKey) => "ret:" + methodKey;

    /// <summary>
    /// The atoms of a path made of <paramref name="parts"/>. A literal naming the game's folder
    /// turns the Documents and environment origins it is combined with into the game's folder, and
    /// marks references, whose origins are only known later, the same way ("game:ATOM").
    /// </summary>
    public static HashSet<string> Combine(IEnumerable<string> parts) {
        var all = parts.ToHashSet(StringComparer.Ordinal);
        if (!all.Remove(GameLiteral)) return all;
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in all)
            result.Add(a switch {
                "documents" or "environment" => "game",
                _ when a.StartsWith("arg:", StringComparison.Ordinal) || a.StartsWith("field:", StringComparison.Ordinal)
                    || a.StartsWith("ret:", StringComparison.Ordinal) || a.StartsWith(TailPrefix, StringComparison.Ordinal)
                    || a.StartsWith(MidPrefix, StringComparison.Ordinal) => "game:" + a,
                _ => a,
            });
        return result;
    }
}
