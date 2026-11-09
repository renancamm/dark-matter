// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using DarkMatter.Pipeline.Scan;

namespace DarkMatter.Pipeline.Report;

/// <summary>
/// <c>darkmatter-pipeline report</c>: an HTML report of a scan, made to be read by people who do not
/// run the tool. It renders a run document (<c>scan --format json</c>, or the copy in the state
/// directory's <c>runs/</c>), or a results file of <c>darkmatter analyze --json</c>, without scanning.
/// <para>
/// Mod names, file names, member names and evidence come from untrusted archives, and the listing
/// names from the snapshot. Every one of them is HTML-encoded, with control and format characters
/// (bidirectional overrides, zero-width characters) shown as escapes, as the text output does, so a
/// name cannot display reordered. The page has no script at all and a Content-Security-Policy that
/// allows none, loads nothing, submits nothing and applies only the page's own style sheet (by
/// hash): a mod whose names hold markup shows that markup as text.
/// </para>
/// </summary>
internal static class ReportCommand {
    static readonly string[] Valued = ["--out", "--title"];

    /// <summary>Evidence lines per label or reason in the page; the JSON has them all.</summary>
    const int Shown = 100;

    static readonly HtmlEncoder Encoder = HtmlEncoder.Default;

    public static int Run(IReadOnlyList<string> argv) {
        var o = Options.Parse(argv, Valued, []);
        if (o.Positional.Count != 1) throw new UsageException("report needs one run document or results file");
        var output = o.Get("--out") ?? throw new UsageException("report needs --out FILE");
        var input = o.Positional[0];
        if (!File.Exists(input)) throw new UsageException($"file not found: {input}");
        var root = JsonNode.Parse(File.ReadAllBytes(input)) as JsonObject ?? throw new InvalidDataException($"{input}: not a JSON object");
        var html = Render(Normalize(root), o.Get("--title") ?? "Dark Matter scan report");
        var tmp = output + ".part";
        File.WriteAllText(tmp, html, new UTF8Encoding(false));
        File.Move(tmp, output, overwrite: true);
        Console.WriteLine($"wrote {output}");
        return 0;
    }

    /// <summary>A run document as it is, or an analyzer results file turned into one (each mod an entry without a release).</summary>
    static JsonObject Normalize(JsonObject root) {
        if (ResultView.Str(root, "kind") == "run") return root;
        if (root["mods"] is not JsonObject mods) throw new InvalidDataException("neither a run document (scan --format json) nor a results file (analyze --json)");
        var releases = new JsonArray();
        foreach (var (name, result) in mods.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            releases.Add(new JsonObject { ["id"] = name, ["name"] = name, ["status"] = "scanned", ["result"] = result?.DeepClone() });
        var stamp = root["stamp"]?.DeepClone();
        return new JsonObject { ["kind"] = "run", ["mode"] = "results file", ["stamp"] = stamp, ["releases"] = releases };
    }

    static string H(string? s) => Encoder.Encode(Text.Printable(s ?? ""));

    /// <summary>The page's Content-Security-Policy: the one style sheet below, by its hash, and nothing else.</summary>
    internal static readonly string Csp =
        $"default-src 'none'; style-src 'sha256-{Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(Css)))}'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'";

    static string? Str(JsonObject? o, string name) => ResultView.Str(o, name);

    static string TierClass(string tier) => tier switch {
        "no-code" => "t-none",
        "limited-access" => "t-limited",
        _ => "t-broad",
    };

    public static string Render(JsonObject run, string title) {
        var entries = (run["releases"] as JsonArray ?? []).OfType<JsonObject>().ToList();
        var withResult = entries.Where(e => e["result"] is JsonObject).Select(e => (Entry: e, View: ResultView.From(e["result"]))).ToList();
        var b = new StringBuilder();
        b.Append("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        b.Append(CultureInfo.InvariantCulture, $"<meta http-equiv=\"Content-Security-Policy\" content=\"{Csp}\">\n");
        b.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<meta name=\"referrer\" content=\"no-referrer\">\n");
        b.Append(CultureInfo.InvariantCulture, $"<title>{H(title)}</title>\n<style>{Css}</style>\n</head>\n<body>\n<main>\n");
        b.Append(CultureInfo.InvariantCulture, $"<header><h1>{H(title)}</h1>\n<p class=\"meta\">{H(Generated(run))}</p></header>\n");
        b.Append(Explainer);

        // Counts.
        b.Append("<section><h2>Summary</h2>\n<div class=\"tiles\">");
        foreach (var (tier, name) in new[] { ("no-code", "No code"), ("limited-access", "Limited access"), ("broad-access", "Broad access") })
            b.Append(CultureInfo.InvariantCulture, $"<div class=\"tile {TierClass(tier)}\"><span class=\"n\">{withResult.Count(x => x.View.Tier == tier)}</span><span>{H(name)}</span></div>");
        b.Append("</div>\n");
        var skipped = entries.Count(e => Str(e, "status") == "skipped");
        var failed = entries.Count(e => Str(e, "status") == "failed");
        b.Append(CultureInfo.InvariantCulture, $"<p>{withResult.Count} mods with a result");
        if (skipped > 0) b.Append(CultureInfo.InvariantCulture, $", {skipped} skipped");
        if (failed > 0) b.Append(CultureInfo.InvariantCulture, $", {failed} not scanned because their archive could not be fetched or verified");
        b.Append(".</p>\n");
        var groupCounts = withResult.SelectMany(x => x.View.Groups.Select(g => g.Name)).GroupBy(n => n).OrderByDescending(g => g.Count()).ToList();
        if (groupCounts.Count > 0) {
            b.Append("<p>Broad-access mods by reason group (a mod counts in every group it has a reason in): ");
            b.Append(string.Join(", ", groupCounts.Select(g => $"{H(g.Key)} {g.Count()}")));
            b.Append(".</p>\n");
        }
        b.Append("</section>\n");

        // Changes.
        var changes = entries.Where(e => e["change"] is JsonObject).ToList();
        if (changes.Count > 0) {
            b.Append("<section><h2>Changes since the last scan</h2>\n<ul class=\"changes\">\n");
            foreach (var e in changes) {
                var c = (JsonObject)e["change"]!;
                var kind = Str(c, "kind");
                var text = kind switch {
                    "new" => "first scan",
                    "gone" => "no longer in the index",
                    "rescanned" => "same release, scanned again: " + ResultDiff.OfChange(c),
                    _ => $"{Str(c, "from")} → {Str(c, "to")}: " + ResultDiff.OfChange(c),
                };
                b.Append(CultureInfo.InvariantCulture, $"<li><strong>{H(Str(e, "name") ?? Str(e, "id"))}</strong> {H(text)}</li>\n");
            }
            b.Append("</ul></section>\n");
        }

        var missing = entries.Where(e => Str(e, "status") is "skipped" or "failed").ToList();
        if (missing.Count > 0) {
            b.Append("<section><h2>Not scanned</h2>\n<ul>\n");
            foreach (var e in missing)
                b.Append(CultureInfo.InvariantCulture, $"<li><strong>{H(Str(e, "name") ?? Str(e, "id"))}</strong> ({H(Str(e, "status"))}): {H(Str(e, "reason"))}</li>\n");
            b.Append("</ul></section>\n");
        }

        // Index of mods.
        if (withResult.Count > 0) {
            b.Append("<section><h2>Mods</h2>\n<table class=\"index\"><thead><tr><th>Mod</th><th>Version</th><th>Tier</th><th>Why</th></tr></thead><tbody>\n");
            int i = 0;
            foreach (var (e, v) in withResult) {
                var rel = e["release"] as JsonObject;
                b.Append(CultureInfo.InvariantCulture, $"<tr><td><a href=\"#m{i++}\">{H(Str(e, "name") ?? Str(e, "id"))}</a></td><td>{H(Str(rel, "version"))}</td>"
                    + $"<td><span class=\"badge {TierClass(v.Tier)}\">{H(v.TierName)}</span></td><td>{H(string.Join(" · ", v.Groups.Select(g => g.Name)))}</td></tr>\n");
            }
            b.Append("</tbody></table></section>\n");
        }

        int n = 0;
        foreach (var (e, v) in withResult) Card(b, e, v, n++);

        b.Append("<footer>\n");
        b.Append(Footer(run));
        b.Append("</footer>\n</main>\n</body>\n</html>\n");
        return b.ToString();
    }

    static string Generated(JsonObject run) {
        var parts = new List<string>();
        if ((Str(run, "finishedAt") ?? Str(run, "startedAt")) is { } at) parts.Add($"Scanned {at}");
        if (run["stamp"] is JsonObject st) {
            if (Str(st["policy"] as JsonObject, "version") is { } pv) parts.Add($"policy {pv}");
            if (Str(st, "tool") is { } tool) parts.Add(tool);
            if (Str(st["game"] as JsonObject, "folder") is { } g) parts.Add($"game {g}");
        }
        if (run["snapshot"] is JsonObject snap && snap["sources"] is JsonObject src && src["generated"] is JsonObject gen
            && gen["commit"] is JsonValue c && c.TryGetValue<string>(out var commit) && commit.Length > 0)
            parts.Add($"index snapshot {commit[..Math.Min(12, commit.Length)]}");
        if (run["snapshot"] is JsonObject kept && Str(kept, "stale") != null) parts.Add("an earlier copy of the index (it may be out of date)");
        return string.Join(" · ", parts);
    }

    static void Card(StringBuilder b, JsonObject e, ResultView v, int n) {
        var rel = e["release"] as JsonObject;
        var name = Str(e, "name") ?? Str(e, "id");
        b.Append(CultureInfo.InvariantCulture, $"<article class=\"card {TierClass(v.Tier)}\" id=\"m{n}\">\n<div class=\"head\"><h3>{H(name)}</h3>");
        b.Append(CultureInfo.InvariantCulture, $"<span class=\"badge {TierClass(v.Tier)}\">{H(v.TierName)}</span></div>\n");
        var meta = new List<string>();
        if (name != Str(e, "id")) meta.Add($"id {Str(e, "id")}");
        if (rel != null) {
            meta.Add($"version {Str(rel, "version")}");
            if (Str(rel, "status") is { } st && st != "stable") meta.Add(st);
            if (Str(rel, "loader") is { } loader) meta.Add($"loader {loader}");
            if (Str(rel, "sha256") is { } sha) meta.Add($"archive sha256 {sha[..Math.Min(16, sha.Length)]}…");
        }
        if (meta.Count > 0) b.Append(CultureInfo.InvariantCulture, $"<p class=\"meta\">{H(string.Join(" · ", meta))}</p>\n");
        b.Append(CultureInfo.InvariantCulture, $"<p class=\"summary\">{H(v.TierSummary)}</p>\n");
        if (v.Tier != "no-code") {
            b.Append(CultureInfo.InvariantCulture, $"<h4>{(v.Tier == "limited-access" ? "Can do" : "Can do (what the check saw, not a complete list)")}</h4>\n<ul class=\"findings\">\n");
            if (v.Labels.Count == 0) b.Append("<li class=\"none\">nothing the check labels</li>\n");
            foreach (var l in v.Labels) Finding(b, l);
            b.Append("</ul>\n");
            foreach (var g in v.Groups) {
                b.Append(CultureInfo.InvariantCulture, $"<h4>{H(g.Name)}</h4>\n<p class=\"group-summary\">{H(g.Summary)}</p>\n<ul class=\"findings\">\n");
                foreach (var r in g.Reasons) Finding(b, r);
                b.Append("</ul>\n");
            }
        }
        if (v.Warnings.Count > 0) {
            b.Append("<ul class=\"warnings\">\n");
            foreach (var w in v.Warnings) b.Append(CultureInfo.InvariantCulture, $"<li>{H(w)}</li>\n");
            b.Append("</ul>\n");
        }
        if (v.Trusted.Count > 0) b.Append(CultureInfo.InvariantCulture, $"<p class=\"meta\">Trusted libraries (by hash): {H(string.Join(", ", v.Trusted))}</p>\n");
        if (v.Files.Count > 0) {
            b.Append(CultureInfo.InvariantCulture, $"<details><summary>{v.Files.Count} code file{(v.Files.Count == 1 ? "" : "s")}</summary>\n<ul class=\"files\">\n");
            foreach (var f in v.Files)
                b.Append(CultureInfo.InvariantCulture, $"<li><code>{H(f.Path)}</code> <span class=\"meta\">{H(f.Classification)} · {H(f.Sha256 is { Length: > 16 } s ? s[..16] + "…" : f.Sha256)}</span></li>\n");
            b.Append("</ul></details>\n");
        }
        b.Append("</article>\n");
    }

    static void Finding(StringBuilder b, FindingView f) {
        b.Append(CultureInfo.InvariantCulture, $"<li><details><summary>{H(f.Text)} <span class=\"count\">{f.Count}</span></summary>\n<ul class=\"evidence\">\n");
        foreach (var e in f.Evidence.Take(Shown)) b.Append(CultureInfo.InvariantCulture, $"<li><code>{H(e)}</code></li>\n");
        if (f.Count > Shown) b.Append(CultureInfo.InvariantCulture, $"<li class=\"more\">… and {f.Count - Shown} more in the JSON results</li>\n");
        b.Append("</ul></details></li>\n");
    }

    static string Footer(JsonObject run) {
        var b = new StringBuilder("<h2>How this was made</h2>\n<dl>\n");
        void Row(string k, string? v) {
            if (!string.IsNullOrEmpty(v)) b.Append(CultureInfo.InvariantCulture, $"<dt>{H(k)}</dt><dd><code>{H(v)}</code></dd>\n");
        }
        if (run["stamp"] is JsonObject st) {
            Row("Tool", Str(st, "tool"));
            Row("Pipeline", Str(st, "pipeline"));
            Row(".NET runtime", Str(st, "runtime"));
            Row("Policy", Str(st["policy"] as JsonObject, "version") is { } v ? $"{v} (sha256 {Str(st["policy"] as JsonObject, "sha256")})" : null);
            Row("Game", Str(st["game"] as JsonObject, "folder") is { } g ? $"{g} (DLL set sha256 {Str(st["game"] as JsonObject, "sha256")})" : null);
            Row("Trusted libraries", st["allowlist"] is JsonObject al && al["files"] is JsonValue files ? $"{files} files (sha256 {Str(al, "sha256")})" : null);
            Row("Scan key", Str(st, "key"));
        }
        if (run["snapshot"] is JsonObject snap) {
            Row("Index snapshot", Str(snap, "source"));
            Row("Snapshot sha256", Str(snap, "sha256"));
            Row("Snapshot not current", Str(snap, "stale"));
        }
        Row("Mode", Str(run, "mode"));
        b.Append("</dl>\n<p class=\"meta\">Dark Matter reads mod code without running it. Each release's archive was checked against the "
            + "SHA-256 the content index stamped for it before it was analyzed. The rules are in policy/policy.jsonc.</p>\n");
        return b.ToString();
    }

    const string Explainer = """
        <section class="explainer">
        <h2>How to read this report</h2>
        <p>Each mod is placed in one of three tiers by what its code can do, as far as the check can account for it.
        <strong>A tier is not a judgement of whether a mod is harmful.</strong> It says what the mod <em>can</em> do, not what it does.
        Many widely used mods are Broad access (loaders, scripting bridges, physics mods, mods with native libraries); for those, trust rests on the author rather than on the check.</p>
        <table>
        <tr><td><span class="badge t-none">No code</span></td><td>Ships no code: parts, planets, textures, sounds. It can't run programs.</td></tr>
        <tr><td><span class="badge t-limited">Limited access</span></td><td>Ships code, and everything it can run was looked at. Its list of what it can do is complete.</td></tr>
        <tr><td><span class="badge t-broad">Broad access</span></td><td>Something in the mod can reach beyond what the check can list, or the check could not look at all. The list is what it saw, not a complete list.</td></tr>
        </table>
        <p>A Broad-access mod says why, in one or more groups. The groups explain the tier; they are not a scale.
        <strong>Deep game access</strong>: works with the game's code and memory in ways the check can't follow all the way, as ordinary modding often does.
        <strong>System access</strong>: uses features that can reach anything on the computer, such as native code or starting programs.
        <strong>Couldn't be fully checked</strong>: part of the mod couldn't be inspected; often a packaging matter the author can fix.</p>
        <p>Open a line to see the evidence behind it: the members of the mod's code where the check found it.</p>
        </section>

        """;

    const string Css = """
        :root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#5f6368;--card:#fff;--line:#e3e3e0;--code:#f3f3f1;
        --none:#5f6b7a;--none-bg:#eef1f4;--lim:#1f6f43;--lim-bg:#e5f3ea;--broad:#a33a1f;--broad-bg:#fbe9e3}
        @media (prefers-color-scheme:dark){:root{--bg:#161618;--fg:#ececec;--muted:#a0a3a8;--card:#1f1f22;--line:#34343a;--code:#2a2a2e;
        --none:#aab4c0;--none-bg:#2a2f36;--lim:#7fd3a0;--lim-bg:#1c3326;--broad:#f2a58e;--broad-bg:#3b231c}}
        *{box-sizing:border-box}
        body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
        main{max-width:960px;margin:0 auto;padding:24px 16px 64px}
        h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:32px 0 10px}h3{font-size:17px;margin:0}h4{font-size:14px;margin:14px 0 4px}
        .meta{color:var(--muted);font-size:13px;margin:2px 0}
        code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 4px;border-radius:4px;overflow-wrap:anywhere}
        .explainer{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 18px 12px}
        .explainer table{border-collapse:collapse}.explainer td{padding:4px 10px 4px 0;vertical-align:top}
        .badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
        .badge.t-none{color:var(--none);background:var(--none-bg)}.badge.t-limited{color:var(--lim);background:var(--lim-bg)}.badge.t-broad{color:var(--broad);background:var(--broad-bg)}
        .tiles{display:flex;gap:10px;flex-wrap:wrap}
        .tile{flex:1 1 140px;border-radius:10px;padding:10px 14px;display:flex;flex-direction:column}
        .tile .n{font-size:28px;font-weight:700}
        .tile.t-none{background:var(--none-bg);color:var(--none)}.tile.t-limited{background:var(--lim-bg);color:var(--lim)}.tile.t-broad{background:var(--broad-bg);color:var(--broad)}
        table.index{width:100%;border-collapse:collapse;font-size:14px}
        table.index th,table.index td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
        table.index a{color:inherit}
        @media (max-width:600px){table.index th:nth-child(4),table.index td:nth-child(4){display:none}}
        .card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;padding:14px 18px;margin:14px 0}
        .card.t-none{border-left-color:var(--none)}.card.t-limited{border-left-color:var(--lim)}.card.t-broad{border-left-color:var(--broad)}
        .card .head{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}
        .summary{margin:6px 0}.group-summary{color:var(--muted);font-size:13px;margin:0 0 4px}
        ul.findings{list-style:none;padding:0;margin:0}
        ul.findings>li{padding:3px 0;border-bottom:1px dashed var(--line)}
        ul.findings>li:last-child{border-bottom:0}
        summary{cursor:pointer}
        .count{color:var(--muted);font-size:12px;margin-left:4px}
        ul.evidence,ul.files{margin:6px 0 6px 6px;padding-left:16px;font-size:12px}
        ul.evidence li{margin:2px 0}
        .more,.none{color:var(--muted)}
        .warnings{color:var(--broad);font-size:13px}
        footer{margin-top:40px;border-top:1px solid var(--line);padding-top:8px}
        footer dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:13px}
        footer dt{color:var(--muted)}footer dd{margin:0;overflow-wrap:anywhere}
        """;
}
