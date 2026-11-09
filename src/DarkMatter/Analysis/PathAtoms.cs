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
    // A reference that something other than a plain copy was made from ("in:arg:..."): a part of it,
    // an edit of it (see Inside).
    const string InsidePrefix = "in:";
    /// <summary>
    /// The Documents folder itself, with nothing appended (the path source "documents"). Followed
    /// directly by the names in the policy's "gameFolder", it is the game's folder (see
    /// <see cref="Gamed"/>); anything else made from it is "documents" (see <see cref="Inside"/>).
    /// </summary>
    public const string DocumentsFolder = "documents-folder";
    const string Documents = "documents";
    const char Separator = '\u001f';

    /// <summary>Types whose values carry a file path: strings, and file-system objects made from one.</summary>
    // Matched by signature name, not gated on the framework (G4): this only decides which fields,
    // parameters and returns path tracing follows. A value of a same-named type defined elsewhere is
    // traced like a path, and gets its atoms from what the mod's code does with it (the path APIs are
    // modelled only for the framework's members, see AssemblyWalker.Models), so it cannot lower a result.
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
    }

    // A text that, joined to what comes before it, can finish a ".." segment ("." or "./x" after a
    // text that may end with "/."), or, joined to what follows, begin one ("x/." or ".").
    [GeneratedRegex(@"^\.([\\/]|$)")]
    private static partial Regex DotFirst();
    [GeneratedRegex(@"(^|[\\/])\.$")]
    private static partial Regex DotLast();

    /// <summary>
    /// Whether texts joined end to end (string.Concat, an interpolated string) can hold a ".."
    /// segment that none of them holds alone. Each part is its text, when the walker knows it (a
    /// literal, null, a constant character), or null. A part whose text is not known can be "." or
    /// empty: next to another such part, or to a known text that ends with "/." or begins with
    /// "./", the two can make "..". <paramref name="inert"/> marks parts whose text is not known
    /// but has a letter or digit and no separator (a number, see MethodWalker.Interpolate), which
    /// cannot be part of a ".." segment.
    /// </summary>
    public static bool Splits(IReadOnlyList<string?> parts, IReadOnlyList<bool> inert) {
        // Runs of known texts, joined, and whether an unknown text that can be dots comes before and after each.
        var runs = new List<(string Text, bool Before, bool After)>();
        bool previousOpen = false;  // the last part that is not a known text can be "." or empty
        System.Text.StringBuilder? run = null;
        for (int i = 0; i < parts.Count; i++) {
            if (parts[i] is { } text) { (run ??= new()).Append(text); continue; }
            bool open = !inert[i];
            if (run != null) {
                runs.Add((run.ToString(), previousOpen, open));
                run = null;
            } else if (open && previousOpen) return true;  // two texts that can each be "." or empty
            previousOpen = open;
        }
        if (run != null) runs.Add((run.ToString(), previousOpen, false));
        foreach (var (text, before, after) in runs) {
            if (Traversal().IsMatch(text)) return true;
            if (before && after && text.Length == 0) return true;
            if (before && DotFirst().IsMatch(text)) return true;
            if (after && DotLast().IsMatch(text)) return true;
        }
        return false;
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
        atoms.Select(Plain).Where(a => a != Head).Select(a => IsReference(a) && !a.StartsWith(TailPrefix, StringComparison.Ordinal) ? TailPrefix + a : a);

    /// <summary>The atoms of a value followed by more of the path: how it ends does not matter there.</summary>
    public static IEnumerable<string> Mid(IEnumerable<string> atoms) =>
        atoms.Select(Plain).Where(a => a != End).Select(a => IsReference(a) && !a.StartsWith(MidPrefix, StringComparison.Ordinal) ? MidPrefix + a : a);

    /// <summary>An origin, where it is no longer the whole path: the Documents folder itself is a path in Documents.</summary>
    public static string Plain(string a) => a == DocumentsFolder ? Documents : a;

    /// <summary>
    /// The atoms of a value made from others by something other than a plain copy (a part of it, an
    /// edit, a file in it): the Documents folder itself becomes a path in Documents, and so does what
    /// a reference holds ("in:ATOM"; one appended to or followed by more already is).
    /// </summary>
    public static IEnumerable<string> Inside(IEnumerable<string> atoms) =>
        atoms.Select(a => a == DocumentsFolder ? Documents : Whole(a) ? InsidePrefix + a : a);

    // A reference that can hold the Documents folder itself: not one already appended, followed by more,
    // made into something else, or followed by the game's folder names.
    static bool Whole(string a) => IsReference(a) && Positioned(a) == null && !a.StartsWith(InsidePrefix, StringComparison.Ordinal)
        && !a.StartsWith(GamePrefix, StringComparison.Ordinal);

    /// <summary>For a reference made into something else ("in:"): the reference itself; null for any other atom.</summary>
    public static string? Made(string a) => a.StartsWith(InsidePrefix, StringComparison.Ordinal) ? a[InsidePrefix.Length..] : null;
    /// <summary>
    /// The atoms of a value followed directly by the game's folder names ("/My Games/Kitten Space
    /// Agency", the policy's "gameFolder"): the Documents folder itself is the game's folder, and
    /// a reference is marked the same way ("game:ATOM"), since what it holds is only known later.
    /// </summary>
    public static IEnumerable<string> Gamed(IEnumerable<string> atoms) =>
        atoms.Select(a => a == DocumentsFolder ? "game" : Whole(a) ? GamePrefix + a : a);

    /// <summary>Whether atoms hold the Documents folder itself, or a reference that can.</summary>
    public static bool MayBeDocumentsFolder(IEnumerable<string> atoms) => atoms.Any(a => a == DocumentsFolder || Whole(a));

    /// <summary>For a reference followed by the game's folder names ("game:"): the reference itself; null for any other atom.</summary>
    public static string? InGame(string a) => a.StartsWith(GamePrefix, StringComparison.Ordinal) ? a[GamePrefix.Length..] : null;
    const string GamePrefix = "game:";

    /// <summary>Whether an atom refers to other values (resolved across the mod) rather than being an origin.</summary>
    public static bool IsReference(string a) => a.StartsWith("arg:", StringComparison.Ordinal) || a.StartsWith("field:", StringComparison.Ordinal)
        || a.StartsWith("ret:", StringComparison.Ordinal) || a.StartsWith(GamePrefix, StringComparison.Ordinal) || a.StartsWith(TailPrefix, StringComparison.Ordinal)
        || a.StartsWith(MidPrefix, StringComparison.Ordinal) || a.StartsWith(InsidePrefix, StringComparison.Ordinal);

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

    /// <summary>The atoms of a path made of <paramref name="parts"/>: those of every part.</summary>
    public static HashSet<string> Combine(IEnumerable<string> parts) => parts.ToHashSet(StringComparer.Ordinal);
}
