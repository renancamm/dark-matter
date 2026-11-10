// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace DarkMatter.Pipeline.Scan;

/// <summary>
/// The text form of a run document: the stamp, the counts, the changes, what was not scanned, and
/// the results (by default only of listings that are new or changed). Every string that comes from
/// the snapshot or a mod is printed with control characters escaped.
/// </summary>
internal static class ScanText {
    /// <summary>Evidence lines shown per label or reason with -v; the JSON has them all.</summary>
    const int Shown = 20;

    // "full-access": the top tier of a run from before policy 36.
    static readonly string[] TierOrder = ["no-code", "limited-access", "broad-access", "full-access"];

    public static string Render(JsonObject run, bool all, bool verbose) {
        var w = new StringBuilder();
        var stamp = run["stamp"] as JsonObject;
        var summary = run["summary"] as JsonObject;
        var releases = (run["releases"] as JsonArray ?? []).OfType<JsonObject>().ToList();
        w.AppendLine(CultureInfo.InvariantCulture, $"Dark Matter scan ({P(Str(run, "mode"))}), {P(Str(run, "startedAt"))}");
        if (run["snapshot"] is JsonObject snap) {
            w.AppendLine(CultureInfo.InvariantCulture, $"  snapshot: {P(Str(snap, "source"))} (sha256 {Short(Str(snap, "sha256"))})");
            if (Str(snap, "stale") is { } stale) w.AppendLine(CultureInfo.InvariantCulture, $"  warning: not the current snapshot: {P(stale)}");
        }
        if (stamp != null) {
            var policy = stamp["policy"] as JsonObject;
            var game = stamp["game"] as JsonObject;
            var allow = stamp["allowlist"] as JsonObject;
            w.AppendLine(CultureInfo.InvariantCulture, $"  stamp: {P(Str(stamp, "tool"))}, policy {P(Str(policy, "version"))} ({Short(Str(policy, "sha256"))}), "
                + $"game {P(Str(game, "folder"))} ({Short(Str(game, "sha256"))}), {allow?["files"]} trusted files, key {Short(Str(stamp, "key"))}");
            if (game?["others"] is JsonArray others && others.Count > 0)
                w.AppendLine(CultureInfo.InvariantCulture, $"  other game builds: {string.Join(", ", others.Select(x => P(Str(x as JsonObject, "folder"))))}");
        }
        if (summary != null) {
            w.AppendLine(CultureInfo.InvariantCulture, $"  {summary["listings"]} listings: {summary["scanned"]} scanned, {summary["cached"]} unchanged since the last scan, "
                + $"{summary["skipped"]} skipped, {summary["failed"]} failed");
            if (summary["tiers"] is JsonObject tiers && tiers.Count > 0)
                w.AppendLine("  tiers: " + string.Join(", ", TierOrder.Where(tiers.ContainsKey).Select(t => $"{tiers[t]} {t}")));
        }

        var changed = releases.Where(r => r["change"] is JsonObject).ToList();
        if (changed.Count > 0) {
            w.AppendLine();
            w.AppendLine("## Changes");
            foreach (var r in changed) {
                var c = (JsonObject)r["change"]!;
                var kind = Str(c, "kind");
                var line = kind switch {
                    "new" => $"new, {Tier(r)}",
                    "gone" => "no longer in the snapshot",
                    "rescanned" => "same release, scanned again: " + Describe(c),
                    _ => $"{P(Str(c, "from") ?? "?")} -> {P(Str(c, "to") ?? "?")}: " + Describe(c),
                };
                w.AppendLine(CultureInfo.InvariantCulture, $"  {P(Str(r, "id"))}{Version(r)}: {line}");
            }
        }
        var missing = releases.Where(r => Str(r, "status") is "skipped" or "failed").ToList();
        if (missing.Count > 0) {
            w.AppendLine();
            w.AppendLine("## Not scanned");
            foreach (var r in missing) w.AppendLine(CultureInfo.InvariantCulture, $"  {P(Str(r, "id"))}{Version(r)}: {Str(r, "status")}: {P(Str(r, "reason") ?? "")}");
        }

        var shown = releases.Where(r => r["result"] is JsonObject && (all || r["change"] is JsonObject)).ToList();
        if (shown.Count > 0) {
            w.AppendLine();
            w.AppendLine(all ? "## Results" : "## Results of new and changed listings (--all for every listing)");
            foreach (var r in shown) Mod(w, r, verbose);
        } else if (!all && releases.Any(r => r["result"] is JsonObject)) {
            w.AppendLine();
            w.AppendLine("No new or changed results (--all shows every listing).");
        }
        return w.ToString();
    }

    static void Mod(StringBuilder w, JsonObject r, bool verbose) {
        var v = ResultView.From(r["result"]);
        void Evidence(FindingView f) {
            if (!verbose) return;
            foreach (var e in f.Evidence.Take(Shown)) w.AppendLine(CultureInfo.InvariantCulture, $"        {P(e)}");
            if (f.Count > Shown) w.AppendLine(CultureInfo.InvariantCulture, $"        ... and {f.Count - Shown} more (--format json has them all)");
        }
        w.AppendLine();
        var release = r["release"] as JsonObject;
        var title = release != null ? $"{P(Str(r, "id"))} {P(Str(release, "version"))}" : P(Str(r, "id"));
        var name = Str(r, "name");
        w.AppendLine($"### {title}: {P(v.TierName)}" + (v.TierNote is { } note ? $" ({P(note)})" : "") + (name != null && name != Str(r, "id") ? $"  ({P(name)})" : ""));
        if (release != null) {
            w.AppendLine($"  release sha256 {P(Str(release, "sha256"))}" + (Str(release, "loader") is { } loader ? $", loader {P(loader)}" : "")
                + (Str(release, "status") is { } st && st != "stable" ? $", {P(st)}" : ""));
        }
        w.AppendLine(CultureInfo.InvariantCulture, $"  {P(v.TierSummary)}");
        Dependencies(w, v);
        if (v.Tier == "no-code") return;
        if (v.Groups.Count > 0) w.AppendLine(CultureInfo.InvariantCulture, $"  Why: {string.Join(" · ", v.Groups.Select(g => P(g.Name)))}");
        w.AppendLine(v.Tier == "limited-access" ? "  Can do:" : "  Can do (not a complete list):");
        if (v.Labels.Count == 0) w.AppendLine("    - nothing the check labels");
        foreach (var l in v.Labels) { w.AppendLine(CultureInfo.InvariantCulture, $"    - {P(l.Text)}"); Evidence(l); }
        foreach (var g in v.Groups) {
            w.AppendLine(CultureInfo.InvariantCulture, $"  {P(g.Name)}: {P(g.Summary)}");
            foreach (var f in g.Reasons) { w.AppendLine(CultureInfo.InvariantCulture, $"    - {P(f.Text)}"); Evidence(f); }
        }
        foreach (var warning in v.Warnings) w.AppendLine(CultureInfo.InvariantCulture, $"  warning: {P(warning)}");
        if (v.Trusted.Count > 0) w.AppendLine(CultureInfo.InvariantCulture, $"  Trusted libraries (by hash; their profiles apply): {string.Join(", ", v.Trusted.Select(P))}");
    }

    // What the mod requires: each dependency with the tier of its own result. A note: it does not change this mod's tier.
    static void Dependencies(StringBuilder w, ResultView v) {
        foreach (var d in v.Dependencies) {
            var state = d.Scanned ? "" : $": {P(d.Reason ?? "no result")}";
            w.AppendLine(CultureInfo.InvariantCulture, $"  Requires {P(d.Id)}{(d.Version != null ? " " + P(d.Version) : "")}{(d.Through != null ? $" (through {P(d.Through)})" : "")}: {P(d.TierName)}{state}");
        }
    }

    static string Tier(JsonObject r) => r["result"] is JsonObject ? ResultView.From(r["result"]).TierName : "?";

    static string Version(JsonObject r) => r["release"] is JsonObject rel ? " " + P(Str(rel, "version") ?? "") : "";

    static string Describe(JsonObject change) => P(ResultDiff.OfChange(change));

    static string? Str(JsonObject? o, string name) => ResultView.Str(o, name);

    static string Short(string? sha) => sha is { Length: > 12 } ? sha[..12] : sha ?? "?";

    static string P(string? s) => Text.Printable(s ?? "");
}
