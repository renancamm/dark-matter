// SPDX-License-Identifier: MIT
using DarkMatter.Evaluation;

namespace DarkMatter.Cli;

/// <summary>Human-readable report of each mod's tier, labels and reasons; with <c>verbose</c>, the evidence behind each.</summary>
internal static class TextReport {
    /// <summary>Evidence lines shown per label or reason; the JSON has them all.</summary>
    const int Shown = 20;

    public static void Print(TextWriter w, IReadOnlyDictionary<string, ModResult> results, bool verbose) {
        void Evidence(Finding f) {
            if (!verbose) return;
            foreach (var e in f.Evidence.Take(Shown)) w.WriteLine($"        {e}");
            if (f.Count > Shown) w.WriteLine($"        ... and {f.Count - Shown} more (--json has them all)");
        }
        foreach (var (name, r) in results) {
            w.WriteLine();
            w.WriteLine($"## {name}: {r.TierName}");
            w.WriteLine($"  {r.TierSummary}");
            if (r.Tier == Tier.NoCode) continue;
            if (r.FullAccess.Count > 0) w.WriteLine($"  Why: {string.Join(" · ", r.FullAccess.Select(g => g.Name))}");
            w.WriteLine(r.Tier == Tier.LimitedAccess ? "  Can do:" : "  Can do (not a complete list):");
            if (r.Labels.Count == 0) w.WriteLine("    - nothing the check labels");
            foreach (var l in r.Labels) { w.WriteLine($"    - {l.Text}"); Evidence(l); }
            foreach (var g in r.FullAccess) {
                w.WriteLine($"  {g.Name}: {g.Summary}");
                foreach (var f in g.Reasons) { w.WriteLine($"    - {f.Text}"); Evidence(f); }
            }
            foreach (var warning in r.Warnings) w.WriteLine($"  warning: {warning}");
            if (r.Trusted.Count > 0) w.WriteLine($"  Trusted libraries (by hash; their profiles apply): {string.Join(", ", r.Trusted)}");
        }
    }
}
