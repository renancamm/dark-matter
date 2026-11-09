// SPDX-License-Identifier: MIT
using System.Security.Cryptography;

namespace DarkMatter.Pipeline.Index;

/// <summary>The outcome of fetching a release's archive: the verified file, or why there is none.</summary>
/// <param name="Path">The verified archive in the store; null when it could not be fetched.</param>
/// <param name="Problem">Why not: "does not match its stamp" or a download error.</param>
/// <param name="Mismatch">A complete download came back with other bytes than the stamp names.</param>
internal sealed record Fetched(string? Path, string? Problem, bool Mismatch);

/// <summary>
/// Release archives verified against their stamp, cached by the stamped SHA-256 in one folder
/// (<c>&lt;sha256&gt;.zip</c>). A release's bytes are what the index stamped or they are not used:
/// a download whose hash differs is deleted, and the next source (the stamp's mirrors) is tried.
/// A cached file is hashed again before each use; one that no longer matches is discarded.
/// </summary>
internal sealed class ArchiveStore(string folder, Http http) {
    public string Folder { get; } = folder;

    /// <summary>The verified archive of <paramref name="release"/>, from the store or downloaded.</summary>
    /// <param name="release">The release whose stamped archive is wanted.</param>
    /// <param name="maxBytes">Size limit; the stamped size, when given and smaller, is the limit instead.</param>
    public async Task<Fetched> Get(Release release, long maxBytes) {
        Directory.CreateDirectory(Folder);
        var path = System.IO.Path.Join(Folder, release.Sha256 + ".zip");
        if (File.Exists(path)) {
            if (Hash(path) == release.Sha256) return new Fetched(path, null, false);
            File.Delete(path);
        }
        var limit = release.Size is { } s && s < maxBytes ? s : maxBytes;
        var problems = new List<string>();
        bool mismatch = false;
        foreach (var url in new[] { release.Url }.Concat(release.Mirrors).Distinct(StringComparer.Ordinal)) {
            var download = path + ".download";
            try {
                var (_, sha) = await http.Download(url, download, limit);
                if (sha == release.Sha256) {
                    File.Move(download, path, overwrite: true);
                    // Hashed once more where it will be read from.
                    if (Hash(path) == release.Sha256) return new Fetched(path, null, false);
                    File.Delete(path);
                    problems.Add($"{url}: changed after it was verified");
                } else {
                    mismatch = true;
                    problems.Add($"{url}: SHA-256 {sha[..12]}..., not the stamped {release.Sha256[..12]}...");
                }
            } catch (Exception e) when (e is FetchException or RateLimitException or IOException or UnauthorizedAccessException) {
                problems.Add(e.Message);
            } finally {
                File.Delete(download);
            }
        }
        return new Fetched(null, (mismatch ? "the archive does not match its stamp: " : "download failed: ") + string.Join("; ", problems), mismatch);
    }

    /// <summary>Lowercase hex SHA-256 of a file, read as a stream.</summary>
    public static string Hash(string path) {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(SHA256.HashData(f));
    }
}
