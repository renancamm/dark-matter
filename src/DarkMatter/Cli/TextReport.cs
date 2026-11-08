// SPDX-License-Identifier: MIT
using DarkMatter.Evaluation;

namespace DarkMatter.Cli;

/// <summary>Human-readable report of each mod's tier, labels and reasons.</summary>
internal static class TextReport {
    public static void Print(TextWriter w, IReadOnlyDictionary<string, ModResult> results, bool verbose) {
        void Evidence(Finding f) {
            if (!verbose) return;
            foreach (var e in f.Evidence) w.WriteLine($"        {e}");
        }
        void Reasons(string heading, IReadOnlyList<Finding> reasons) {
            if (reasons.Count == 0) return;
            w.WriteLine(heading);
            foreach (var f in reasons) { w.WriteLine($"    - {f.Text}"); Evidence(f); }
        }
        foreach (var (name, r) in results) {
            w.WriteLine();
            w.WriteLine($"## {name}: {r.TierName}");
            if (r.Tier == Tier.ContentOnly) { w.WriteLine("  Ships no code."); continue; }
            if (r.Tier == Tier.Unverified)
                w.WriteLine("  The check found nothing that reaches outside the game, but it cannot rule that out: the labels are what it saw, not a complete list.");
            w.WriteLine(r.Tier == Tier.KnownAccess ? "  Can do:" : "  Can do (not a complete list):");
            if (r.Labels.Count == 0) w.WriteLine("    - nothing the check labels");
            foreach (var l in r.Labels) { w.WriteLine($"    - {l.Text}"); Evidence(l); }
            Reasons("  Full access because it:", r.FullAccess);
            Reasons(r.Tier == Tier.FullAccess ? "  Also unverified because it:" : "  Unverified because it:", r.Unverified);
            foreach (var warning in r.Warnings) w.WriteLine($"  warning: {warning}");
            if (r.Trusted.Count > 0) w.WriteLine($"  Trusted libraries (by hash; their profiles apply): {string.Join(", ", r.Trusted)}");
        }
    }
}
