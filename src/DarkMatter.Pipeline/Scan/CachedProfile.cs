// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace DarkMatter.Pipeline.Scan;

/// <summary>
/// A structural check of a profile <c>scan</c> kept in the state folder, before it is used again: it
/// parses, has the format and policy the analyzer expects, and has the parts the analyzer reads,
/// not empty where a profile of a real game or library never is. A profile that fails is deleted
/// and made again. This catches damage and stale files; it is not an integrity check. The state
/// folder is trusted: anyone who can edit a profile can as easily edit a
/// stored result, and a hash next to it would be recomputed with it. The format is the one the
/// analyzer reports (<c>darkmatter version</c>, <c>profileFormat</c>), not a copy kept here. A
/// profile the analyzer has just made is checked the same way; one that fails ends the run.
/// </summary>
internal static class CachedProfile {
    /// <summary>
    /// Why the game profile at <paramref name="path"/> cannot be used, or null when it can.
    /// <paramref name="complete"/>: it must also list no game file it could not read (true for a
    /// profile kept in the state folder).
    /// </summary>
    public static string? GameProblem(string path, string policySha, int format, bool complete = true) => Problem(path, policySha, format, root =>
        NonEmpty(root, "methods", JsonValueKind.Object)
        ?? NonEmpty(root, "assemblies", JsonValueKind.Array)
        ?? NonEmpty(root, "types", JsonValueKind.Array)
        ?? NonEmpty(root, "members", JsonValueKind.Object)
        ?? Present(root, "bases", JsonValueKind.Object)
        ?? Present(root, "inlineArrays", JsonValueKind.Object)
        ?? Present(root, "memberTypes", JsonValueKind.Object)
        ?? Present(root, "interfaces", JsonValueKind.Object)
        ?? Present(root, "skipped", JsonValueKind.Array)
        // scan never keeps a game profile that could not read every game file.
        ?? (complete && root.GetProperty("skipped").GetArrayLength() > 0 ? "it lists game files it could not read" : null));

    /// <summary>Why the library profile at <paramref name="path"/> cannot be used, or null when it can.</summary>
    public static string? LibraryProblem(string path, string policySha, int format) => Problem(path, policySha, format, root => {
        if ((Present(root, "libraries", JsonValueKind.Object) ?? Present(root, "native", JsonValueKind.Object)) is { } missing) return missing;
        var libraries = root.GetProperty("libraries");
        if (!libraries.EnumerateObject().Any() && !root.GetProperty("native").EnumerateObject().Any()) return "it has no libraries";
        foreach (var lib in libraries.EnumerateObject()) {
            if (lib.Value.ValueKind != JsonValueKind.Object) return $"library {lib.Name} is not an object";
            if ((Present(lib.Value, "name", JsonValueKind.String) ?? Present(lib.Value, "assembly", JsonValueKind.String) ?? Present(lib.Value, "types", JsonValueKind.Object)
                ?? Present(lib.Value, "forwarded", JsonValueKind.Array) ?? Present(lib.Value, "members", JsonValueKind.Object)) is { } part)
                return $"library {lib.Name}: {part}";
        }
        return null;
    });

    static string? Problem(string path, string policySha, int expected, Func<JsonElement, string?> parts) {
        try {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return "not a JSON object";
            if (!root.TryGetProperty("format", out var f) || f.ValueKind != JsonValueKind.Number || !f.TryGetInt32(out var format) || format != expected)
                return $"format {(root.TryGetProperty("format", out var g) ? g.GetRawText() : "missing")}, not {expected}";
            var sha = root.TryGetProperty("stamp", out var st) && st.ValueKind == JsonValueKind.Object && st.TryGetProperty("policy", out var p) && p.ValueKind == JsonValueKind.Object
                && p.TryGetProperty("sha256", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
            if (sha != policySha) return $"made with policy sha256 {sha ?? "(missing)"}, not the current {policySha}";
            return parts(root);
        } catch (JsonException e) {
            return "not valid JSON: " + e.Message;
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            return "cannot be read: " + e.Message;
        }
    }

    static string? Present(JsonElement o, string name, JsonValueKind kind) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == kind ? null : $"no {name} {(kind == JsonValueKind.Array ? "list" : kind == JsonValueKind.String ? "text" : "object")}";

    static string? NonEmpty(JsonElement o, string name, JsonValueKind kind) =>
        Present(o, name, kind) ?? ((kind == JsonValueKind.Array ? o.GetProperty(name).GetArrayLength() : o.GetProperty(name).EnumerateObject().Count()) == 0 ? $"{name} is empty" : null);
}
