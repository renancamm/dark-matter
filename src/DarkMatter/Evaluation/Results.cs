// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>A code file of a mod; <see cref="Facts"/> is null if it was listed but not analyzed.</summary>
internal sealed record ModFile(string Path, AssemblyFacts? Facts);

/// <summary>A mod to evaluate: its code files, the archives that could not be extracted, and the scripts it ships.</summary>
internal sealed record ModInput(string Name, IReadOnlyList<ModFile> Files, IReadOnlyList<string> Unextracted, IReadOnlyList<string> Scripts);

/// <summary>A label, or a Full-access or Unverified reason, with examples of what caused it.</summary>
internal sealed record Finding(string Text, IReadOnlyList<string> Evidence);

/// <summary>A code file as analyzed: its SHA-256 is what a loader checks before loading it (docs/loader-spec.md).</summary>
internal sealed record FileResult(string Path, string? Sha256, string? Name, FileClass? Classification);

/// <summary>
/// A mod's tier and why. <see cref="FullAccess"/> and <see cref="Unverified"/> are the reasons of
/// each tier, both kept whatever the tier is; the tier is the highest one with a reason.
/// </summary>
internal sealed record ModResult(
    Tier Tier,
    string TierName,
    IReadOnlyList<Finding> Labels,
    IReadOnlyList<Finding> FullAccess,
    IReadOnlyList<Finding> Unverified,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Trusted,
    IReadOnlyList<FileResult> Files);
