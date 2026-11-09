// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>
/// A code file of a mod; <see cref="Facts"/> is null if it was listed but not analyzed.
/// <see cref="Path"/> is the path shown in results: relative to the mod's folder when it came from a manifest.
/// </summary>
internal sealed record ModFile(string Path, AssemblyFacts? Facts);

/// <summary>A mod to evaluate: its code files, the archives that could not be extracted, and the scripts it ships.</summary>
internal sealed record ModInput(string Name, IReadOnlyList<ModFile> Files, IReadOnlyList<string> Unextracted, IReadOnlyList<string> Scripts);

/// <summary>
/// A label or a Full-access reason: its stable id (a label id, or the capability, finding or
/// combination id of a reason), its text for the user, and every piece of evidence behind it,
/// distinct and in ordinal order, so two results can be compared line by line.
/// </summary>
internal sealed record Finding(string Id, string Text, IReadOnlyList<string> Evidence) {
    /// <summary>How many pieces of evidence there are (displays show the first few).</summary>
    public int Count => Evidence.Count;

    public static Finding Of(string id, string text, IEnumerable<string> evidence) =>
        new(id, text, [.. evidence.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)]);
}

/// <summary>A code file as analyzed: its SHA-256 is what a loader checks before loading it.</summary>
internal sealed record FileResult(string Path, string? Sha256, string? Name, FileClass? Classification);

/// <summary>The Full-access reasons of one policy group ("system-access"), with its name and summary for the user.</summary>
internal sealed record GroupResult(string Group, string Name, string Summary, IReadOnlyList<Finding> Reasons);

/// <summary>
/// A mod's tier and why. <see cref="FullAccess"/> holds every group with a reason, in policy
/// order; the mod is Full access when it is not empty.
/// </summary>
internal sealed record ModResult(
    Tier Tier,
    string TierName,
    string TierSummary,
    IReadOnlyList<Finding> Labels,
    IReadOnlyList<GroupResult> FullAccess,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Trusted,
    IReadOnlyList<FileResult> Files);
