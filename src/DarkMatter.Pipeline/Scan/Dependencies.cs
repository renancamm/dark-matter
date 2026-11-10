// SPDX-License-Identifier: MIT
using System.Text.Json.Nodes;

namespace DarkMatter.Pipeline.Scan;

/// <summary>
/// A mod's required dependencies in its result: a note, not part of the tier (pipeline 0.3.11; from 0.3.9 a
/// dependency raised the mod's tier). The result keeps the tier, labels and reasons the analyzer gave the mod's own
/// code. Each required dependency, and what it requires in turn, is listed under "dependencies" with the tier
/// of its own code, so a reader sees what else is installed with the mod and can look that result up. Only
/// "required" dependencies are listed: a recommended or suggested mod is the player's choice. The dependency's
/// release is the one this run scanned (the newest), or, when scanning one mod, the listing's last stored result;
/// one with no result is listed as not scanned.
/// </summary>
internal static partial class ScanCommand {
    /// <summary>
    /// The analyzer's own result of a stored result: no dependencies, and the mod's own tier back in place for a
    /// result stored by pipeline 0.3.9 or 0.3.10, which kept it under "own" when a dependency had raised the tier.
    /// </summary>
    static JsonObject OwnResult(JsonNode result) {
        var o = (JsonObject)result.DeepClone();
        if (o["own"] is JsonObject own)
            foreach (var key in new[] { "tier", "tierName", "tierSummary" })
                if (own[key] is { } value) o[key] = value.DeepClone();
        o.Remove("own");
        o.Remove("dependencies");
        return o;
    }

    /// <summary>
    /// Gives every entry with a result and required dependencies its combined result (see the class comment).
    /// <paramref name="stored"/> answers for a listing that is not in this run: its last stored result, or null.
    /// </summary>
    static void ApplyDependencies(List<Entry> entries, Func<string, JsonObject?> stored) {
        var byId = entries.Where(e => e.Result != null && e.Release != null).ToDictionary(e => e.Id, StringComparer.Ordinal);
        var own = byId.ToDictionary(kv => kv.Key, kv => OwnResult(kv.Value.Result!), StringComparer.Ordinal);
        var done = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        var visiting = new HashSet<string>(StringComparer.Ordinal);

        JsonObject Combined(string id) {
            if (done.TryGetValue(id, out var ready)) return ready;
            var result = (JsonObject)own[id].DeepClone();
            // A cycle of requirements: each member is installed with the others; its own result stands in.
            if (!visiting.Add(id)) return result;
            var required = byId[id].Release!.Dependencies.Where(d => d.Kind == "required").ToList();
            var listed = new JsonArray();
            var seen = new HashSet<string>(StringComparer.Ordinal) { id };
            void Add(JsonObject dependency) {
                if (seen.Add(ResultView.Str(dependency, "id") ?? "")) listed.Add(dependency);
            }
            foreach (var d in required) {
                JsonObject? of = byId.ContainsKey(d.Id) ? Combined(d.Id) : stored(d.Id);
                string? version = byId.TryGetValue(d.Id, out var entry) ? entry.Release!.Version : ResultView.Str(of, "version");
                if (of == null || ResultView.Str(of, "tier") == null) {
                    Add(new JsonObject {
                        ["id"] = d.Id,
                        ["kind"] = d.Kind,
                        ["min"] = d.Min,
                        ["status"] = "not scanned",
                        ["tierName"] = "Not scanned",
                        ["reason"] = "this required mod has no result (it is not in the index snapshot, or its scan failed)",
                    });
                    continue;
                }
                Add(new JsonObject {
                    ["id"] = d.Id,
                    ["version"] = version,
                    ["kind"] = d.Kind,
                    ["min"] = d.Min,
                    ["status"] = "scanned",
                    // (A result stored by pipeline 0.3.9 or 0.3.10 keeps the mod's own tier under "own".)
                    ["tier"] = ResultView.Str(of["own"] as JsonObject ?? of, "tier"),
                    ["tierName"] = ResultView.Str(of["own"] as JsonObject ?? of, "tierName"),
                });
                // What the dependency requires in turn is installed too.
                foreach (var further in (of["dependencies"] as JsonArray ?? []).OfType<JsonObject>()) {
                    var copy = (JsonObject)further.DeepClone();
                    copy["through"] ??= d.Id;
                    Add(copy);
                }
            }
            if (listed.Count > 0) result["dependencies"] = listed;
            visiting.Remove(id);
            return done[id] = result;
        }

        foreach (var (id, e) in byId) e.Result = Combined(id);
    }

    /// <summary>A listing's last stored result with its version (for a dependency that is not in this run), or null.</summary>
    static JsonObject? StoredLatest(Settings s, JsonObject latest, string id) {
        if (latest[id] is not JsonObject entry || ResultView.Str(entry, "sha256") is not { } sha || !Sha256Hex().IsMatch(sha)) return null;
        if (!NamePattern().IsMatch(id) || LoadResult(s, id, sha.ToLowerInvariant())?["result"] is not JsonObject result || !Tiered(result)) return null;
        var copy = (JsonObject)result.DeepClone();
        copy["version"] = ResultView.Str(entry, "version");
        return copy;
    }
}
