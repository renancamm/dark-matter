// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using DarkMatter.Pipeline.Extract;
using DarkMatter.Pipeline.Index;

namespace DarkMatter.Pipeline.Scan;

/// <summary>
/// <c>darkmatter-pipeline scan</c>: analyze the content index, or one mod, from the index's snapshot.
/// <list type="bullet">
/// <item><c>scan index</c>: the newest release of every listing (stable first, yanked releases
/// skipped). A release that already has a result under the current scan key is not scanned again,
/// so a second run rescans nothing until a release, the policy, the tool, the game or the
/// allowlist changes; <c>--full</c> rescans everything.</item>
/// <item><c>scan mod ID[@VERSION]</c>: one listing's newest release, or the given version.</item>
/// <item><c>scan mod PATH...</c>: a local folder, zip or DLLs (an unreleased build). It has no
/// stamp, so it is identified by its files' hashes and its result is not stored.</item>
/// </list>
/// Each release's archive is verified against its stamped SHA-256 before anything else; one that
/// cannot be fetched or does not match is reported as not scanned, never analyzed in its place.
/// Everything is kept in the state directory: the snapshot, verified archives, extracted trees,
/// the allowlist and library files, the profiles, results by release, and one document per run.
/// One scan at a time uses a state directory (a lock file); a second one is refused. The analyzer
/// runs as a separate process (<see cref="AnalyzerProcess"/>).
/// </summary>
internal static partial class ScanCommand {
    static readonly string[] Valued = ["--game", "--state", "--snapshot", "--format", "--out", "--analyzer", "--max-bytes", "--max-extracted-bytes", "--retries", "--name"];
    static readonly string[] Flags = ["--full", "--all", "-v", "--verbose"];

    /// <summary>Version of the run and result documents.</summary>
    public const int Schema = 1;

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")]
    private static partial Regex NamePattern();

    [GeneratedRegex("^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256Hex();

    static string PipelineVersion =>
        "darkmatter-pipeline " + (typeof(ScanCommand).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "?");

    sealed class Settings {
        public required string State { get; init; }
        public required string Game { get; init; }
        public required string SnapshotSource { get; init; }
        public required bool Full { get; init; }
        public required bool All { get; init; }
        public required bool Verbose { get; init; }
        public required string Format { get; init; }
        public required string? Out { get; init; }
        public required long MaxBytes { get; init; }
        public required ExtractCommand.Limits Limits { get; init; }
        public required AnalyzerProcess Analyzer { get; init; }
        public required Http Http { get; init; }

        /// <summary>This run's own folder for the analyzer's manifest and results, deleted at the end.</summary>
        public required string Work { get; init; }

        public string Dir(params string[] parts) => Path.Join([State, .. parts]);
    }

    /// <summary>
    /// Everything a scan's results depend on, prepared once per run. <c>Incomplete</c> says why the
    /// game profile is not complete (game files it could not read), or is null: such a profile is used
    /// for this run only, and results made with it are marked to be retried.
    /// </summary>
    sealed record Context(Snapshot Snapshot, ArchiveStore Store, string Allowlist, string? LibraryProfile, string GameProfile, string Key, JsonObject Stamp,
        string? Incomplete = null, bool ProfileReused = false);

    /// <summary>One listing (or local mod) in a run.</summary>
    sealed class Entry {
        public required string Id { get; init; }
        public string Name { get; init; } = "";
        public Release? Release { get; init; }
        public JsonObject? Identity { get; init; }
        public string Status { get; set; } = "pending";  // scanned, cached, skipped, failed
        public string? Reason { get; set; }
        public JsonNode? Result { get; set; }
        public JsonObject? Change { get; set; }
        public ManifestMod? Manifest { get; set; }

        /// <summary>Why this result is not reused by the next run (a read or extraction error that may be passing); null if it can be.</summary>
        public string? Retry { get; set; }

        /// <summary>Errors from the file system (not from the archive's contents) while extracting.</summary>
        public List<string> EnvironmentErrors { get; } = [];

        /// <summary>The listing's last recorded release (from latest.json) and its stored result, read before this run stores anything.</summary>
        public JsonObject? Before { get; set; }
        public JsonNode? BeforeResult { get; set; }
    }

    public static async Task<int> Run(IReadOnlyList<string> argv) {
        if (argv.Count == 0 || argv[0] is not ("index" or "mod")) throw new UsageException("scan needs a mode: index, or mod ID[@VERSION] | PATH...");
        var mode = argv[0];
        var o = Options.Parse(argv.Skip(1).ToList(), Valued, Flags);
        var game = o.Get("--game") ?? throw new UsageException("scan needs --game DIR (the game folder whose DLLs the game profile is made from)");
        if (!Directory.Exists(game)) throw new UsageException($"game folder not found: {game}");
        var format = o.Get("--format") ?? "text";
        if (format is not ("text" or "json")) throw new UsageException("--format is text or json");
        if (mode == "index" && o.Positional.Count > 0) throw new UsageException($"scan index takes no arguments, not {o.Positional[0]}");
        if (mode == "mod" && o.Positional.Count == 0) throw new UsageException("scan mod needs a listing id (ID or ID@VERSION) or local files (PATH...)");
        using var http = new Http(attempts: (int)o.Number("--retries", 3, 0) + 1, pause: TimeSpan.FromSeconds(1.5), timeout: TimeSpan.FromSeconds(180));
        var state = Path.GetFullPath(o.Get("--state") ?? "darkmatter-state");
        Directory.CreateDirectory(state);
        using var stateLock = LockState(state);
        var started = DateTimeOffset.UtcNow;
        var s = new Settings {
            State = state,
            Game = game,
            SnapshotSource = o.Get("--snapshot") ?? Snapshot.DefaultUrl,
            Full = o.Has("--full"),
            All = o.Has("--all"),
            Verbose = o.Has("-v", "--verbose"),
            Format = format,
            Out = o.Get("--out"),
            MaxBytes = o.Number("--max-bytes", 4L << 30, 1),
            Limits = ExtractCommand.Limits.Default with { MaxBytes = o.Number("--max-extracted-bytes", ExtractCommand.Limits.Default.MaxBytes, 1) },
            Analyzer = new AnalyzerProcess(o.Get("--analyzer") ?? AnalyzerProcess.DefaultPath),
            Http = http,
            Work = Path.Join(state, "work", $"{started.ToString("yyyyMMdd'T'HHmmssfff", CultureInfo.InvariantCulture)}-{Environment.ProcessId}"),
        };
        // Work folders of earlier runs that were stopped before they could delete theirs: this run
        // holds the lock, so none of them is in use.
        if (Directory.Exists(s.Dir("work")))
            foreach (var old in Directory.GetDirectories(s.Dir("work"))) DeleteWork(old);
        try {
            return await Run(s, mode, o, started);
        } finally {
            // A folder that cannot be deleted must not replace the run's own outcome or exception.
            DeleteWork(s.Work);
        }
    }

    static void DeleteWork(string folder) {
        try {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        } catch (Exception x) when (x is IOException or UnauthorizedAccessException) {
            Console.Error.WriteLine($"warning: cannot delete the work folder {folder}: {x.Message}");
        }
    }

    static async Task<int> Run(Settings s, string mode, Options o, DateTimeOffset started) {
        var ctx = await Prepare(s);

        List<Entry> entries;
        bool local = false;
        if (mode == "index") {
            entries = await ScanReleases(s, ctx, [.. ctx.Snapshot.Listings.Select(l => (l, (string?)null))], updateLatest: true);
            // A listing whose id cannot name a folder is not scanned, and says so: it fails, like a
            // listing whose archive cannot be fetched, rather than drop out of the run.
            entries.AddRange(ctx.Snapshot.Rejected.Select(r => new Entry { Id = r.Id, Status = "failed", Reason = r.Reason }));
        } else if (o.Positional.Any(p => File.Exists(p) || Directory.Exists(p))) {
            local = true;
            entries = [ScanLocal(s, ctx, o.Positional, o.Get("--name"))];
        } else {
            if (o.Positional.Count != 1) throw new UsageException("scan mod takes one listing id, or local files (none of these exist)");
            var (id, version) = o.Positional[0].Split('@', 2) is var p && p.Length == 2 ? (p[0], (string?)p[1]) : (o.Positional[0], null);
            var listing = ctx.Snapshot.Listings.FirstOrDefault(l => string.Equals(l.Id, id, StringComparison.OrdinalIgnoreCase))
                ?? throw new UsageException($"{Text.Quote(id)} is neither a listing in the snapshot nor a file or folder");
            entries = await ScanReleases(s, ctx, [(listing, version)], updateLatest: version == null);
        }

        var run = RunDocument(mode, local, started, ctx, entries);
        var saved = RunPath(s.Dir("runs"), started, mode);
        Text.WriteJson(saved, run);
        var output = s.Format == "json"
            ? JsonSerializer.Serialize(run, Text.Json) + "\n"
            : ScanText.Render(run, mode == "mod" || s.All, s.Verbose);
        if (s.Out != null) {
            File.WriteAllText(s.Out, output);
            Console.Error.WriteLine($"wrote {s.Out}");
        } else {
            Console.Out.Write(output);
        }
        Console.Error.WriteLine($"run saved to {saved}");
        return entries.Any(e => e.Status == "failed") ? 1 : 0;
    }

    /// <summary>
    /// Holds the state directory's lock file for the run. Two scans on one state directory would
    /// share its extracted trees, results and latest.json, so the second one is refused.
    /// </summary>
    static FileStream LockState(string state) {
        var path = Path.Join(state, "lock");
        try {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        } catch (IOException e) {
            throw new StateBusyException($"another scan is using the state folder {state} (its lock file {path} is held): {e.Message}");
        }
    }

    /// <summary>A new file name for this run's document: runs started in the same millisecond get a counter, never each other's file.</summary>
    static string RunPath(string runs, DateTimeOffset started, string mode) {
        Directory.CreateDirectory(runs);
        var stem = $"{started.ToString("yyyyMMdd'T'HHmmss.fff'Z'", CultureInfo.InvariantCulture)}-{mode}";
        for (int n = 0; ; n++) {
            var path = Path.Join(runs, n == 0 ? stem + ".json" : $"{stem}-{n}.json");
            try {
                using (new FileStream(path, FileMode.CreateNew, FileAccess.Write)) { }
                return path;
            } catch (IOException) when (File.Exists(path)) {
                // taken: try the next name
            }
        }
    }

    /// <summary>The snapshot, the allowlist and library files, the analyzer's stamp, the game and library profiles, and the scan key.</summary>
    static async Task<Context> Prepare(Settings s) {
        var log = Console.Error;
        var snapshot = await SnapshotSource.Load(s.Http, s.SnapshotSource, s.Dir("snapshot.json"), log);
        log.WriteLine($"snapshot: {snapshot.Describe()}, {snapshot.Listings.Count} listings");
        var store = new ArchiveStore(s.Dir("archives"), s.Http);

        log.WriteLine("allowlist: trust anchors from the snapshot");
        var built = await AllowlistBuilder.Build(snapshot, store, AllowlistBuilder.Anchors.Default, s.Dir("libraries"), 1L << 30, log);
        var allowlist = s.Dir("allowlist.json");
        Text.WriteJson(allowlist, built.Document);
        var libraries = built.Document["libraries"]!.AsObject();
        var trusted = libraries.Select(kv => kv.Key).Order(StringComparer.Ordinal).ToList();
        // The analyzer uses each trusted file's names as well as its hash (impersonation, the
        // trusted boundary, which versions are trusted): the key covers both.
        var allowKey = Sha(string.Join("\n", trusted.Select(h => h + "\t" + string.Join("\t", AllowlistBuilder.Names(libraries[h])))));
        if (built.Failed > 0) log.WriteLine($"warning: {built.Failed} trust-anchor versions could not be verified; calls into them count as not analyzed");

        var version = JsonNode.Parse(s.Analyzer.Check(["version"], "darkmatter version"))!.AsObject();
        var policySha = version["policy"]?["sha256"]?.ToString() ?? throw new AnalyzerException("darkmatter version gave no policy hash");
        var tool = version["tool"]?.ToString() ?? "?";
        var runtime = version["runtime"]?.ToString() ?? "?";
        // The profile format this analyzer build writes and reads: kept profiles are checked against it.
        var profileFormat = version["profileFormat"] is JsonValue pf && pf.TryGetValue<int>(out var n) ? n
            : throw new AnalyzerException("darkmatter version gave no profile format (an analyzer older than this pipeline?)");

        // The game: its DLLs (what `darkmatter profile` reads), by name and hash.
        var gameDlls = Directory.GetFiles(s.Game, "*.dll").Order(StringComparer.Ordinal).ToList();
        if (gameDlls.Count == 0) throw new UsageException($"no DLLs in the game folder {s.Game}");
        var gameKey = Sha(string.Join("\n", gameDlls.Select(p => Path.GetFileName(p) + "\t" + ArchiveStore.Hash(p))));
        var profiles = s.Dir("profiles");
        Directory.CreateDirectory(profiles);
        // The analyzer's and the pipeline's own assemblies, by hash: a code change without a version
        // bump (or another build passed as --analyzer) is a new key, not a reused result.
        var analyzerSha = ArchiveStore.Hash(s.Analyzer.Dll);
        var pipelineSha = PipelineAssemblyHash();
        var toolKey = Sha($"{tool}|{runtime}|{policySha}|{analyzerSha}");
        var gameProfile = Path.Join(profiles, $"game-{Sha($"{toolKey}|{gameKey}")[..20]}.json");
        string? incomplete = null;
        // A cached profile is checked before it is used again (--full makes it again anyway); the
        // library profiles are made with the game profile, so they are made again with it.
        bool remade = DropCached(gameProfile, "game profile", s.Full ? "--full" : null, p => CachedProfile.GameProblem(p, policySha, profileFormat), log);
        if (!File.Exists(gameProfile)) {
            remade = true;
            log.WriteLine($"game profile: {gameDlls.Count} DLLs in {s.Game}");
            var list = Path.Join(profiles, "game-files.txt");
            File.WriteAllLines(list, gameDlls.Select(Path.GetFullPath));
            Profile(s, ["profile", "--out", gameProfile + ".part", "@" + list], gameProfile + ".part", "game profile");
            // A game file the analyzer could not read (it may be one being updated, or locked) is left
            // out of the profile, so calls into it count as not analyzed. That may be passing: the
            // profile is used for this run only, not kept under the key, and its results are retried.
            var skipped = Skipped(gameProfile + ".part");
            // A profile just made is checked as a kept one would be next run: one that fails ends this
            // run (it is neither used nor made again in a loop).
            Fresh(gameProfile + ".part", "game profile", CachedProfile.GameProblem(gameProfile + ".part", policySha, profileFormat, complete: skipped == null));
            if (skipped != null) {
                incomplete = $"the game profile could not read {skipped}";
                log.WriteLine($"warning: {incomplete}; calls into it count as not analyzed, the profile is not kept and results are scanned again next run");
                Directory.CreateDirectory(s.Work);
                var temporary = Path.Join(s.Work, Path.GetFileName(gameProfile));
                File.Move(gameProfile + ".part", temporary, overwrite: true);
                gameProfile = temporary;
            } else {
                File.Move(gameProfile + ".part", gameProfile, overwrite: true);
            }
        }
        var libraryFiles = trusted
            .Select(h => s.Dir("libraries", h))
            .Where(Directory.Exists)
            .SelectMany(d => Directory.GetFiles(d).Where(f => !f.EndsWith(".part", StringComparison.Ordinal)))
            .Order(StringComparer.Ordinal).ToList();
        string? libraryProfile = null;
        bool libraryMade = false;
        if (libraryFiles.Count > 0) {
            libraryProfile = Path.Join(profiles, $"libraries-{Sha($"{toolKey}|{gameKey}|{allowKey}")[..20]}.json");
            // Made with an incomplete game profile, the library profiles are not kept either.
            if (incomplete != null) libraryProfile = Path.Join(s.Work, Path.GetFileName(libraryProfile));
            DropCached(libraryProfile, "library profile", s.Full ? "--full" : remade ? "the game profile was made again" : null,
                p => CachedProfile.LibraryProblem(p, policySha, profileFormat), log);
            if (!File.Exists(libraryProfile)) {
                libraryMade = true;
                log.WriteLine($"library profiles: {libraryFiles.Count} trusted files");
                var list = Path.Join(profiles, "library-files.txt");
                File.WriteAllLines(list, libraryFiles);
                Profile(s, ["profile", "--library", "--allowlist", allowlist, "--game-profile", gameProfile, "--out", libraryProfile + ".part", "@" + list], libraryProfile + ".part", "library profile");
                Fresh(libraryProfile + ".part", "library profile", CachedProfile.LibraryProblem(libraryProfile + ".part", policySha, profileFormat));
                File.Move(libraryProfile + ".part", libraryProfile, overwrite: true);
            }
        }

        var pipeline = PipelineVersion;
        // The extraction limits decide whether a large archive counts as extracted (Broad access if not).
        var limits = s.Limits;
        var key = Sha($"{pipeline}|{pipelineSha}|{toolKey}|{gameKey}|{allowKey}|{limits.MaxDepth}|{limits.MaxBytes}|{limits.MaxFiles}");
        var stamp = new JsonObject {
            ["key"] = key,
            ["tool"] = tool,
            ["pipeline"] = pipeline,
            ["runtime"] = runtime,
            ["build"] = new JsonObject { ["analyzer"] = analyzerSha, ["pipeline"] = pipelineSha },
            ["policy"] = version["policy"]!.DeepClone(),
            ["game"] = new JsonObject { ["folder"] = Path.GetFileName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(s.Game))), ["sha256"] = gameKey, ["dlls"] = gameDlls.Count },
            ["allowlist"] = new JsonObject { ["sha256"] = allowKey, ["files"] = trusted.Count, ["unverified"] = built.Failed },
            ["extraction"] = new JsonObject { ["maxDepth"] = limits.MaxDepth, ["maxBytes"] = limits.MaxBytes, ["maxFiles"] = limits.MaxFiles },
        };
        // A profile kept from an earlier run passed the structural check, but the analyzer may still reject it.
        bool reused = !remade || (libraryProfile != null && !libraryMade);
        return new Context(snapshot, store, allowlist, libraryProfile, gameProfile, key, stamp, incomplete, reused);
    }

    /// <summary>SHA-256 of the pipeline's own assembly (the running program when it is a single file).</summary>
    static string PipelineAssemblyHash() {
        var path = typeof(ScanCommand).Assembly.Location is { Length: > 0 } l ? l : Environment.ProcessPath;
        return path != null && File.Exists(path) ? ArchiveStore.Hash(path) : throw new IOException("cannot find the pipeline's own assembly to stamp results with");
    }

    /// <summary>
    /// Deletes the cached profile at <paramref name="path"/> when it is to be made again (for the
    /// reason <paramref name="remake"/>, null for none) or fails its <paramref name="problem"/>
    /// check, saying why. Returns whether it deleted one.
    /// </summary>
    static bool DropCached(string path, string what, string? remake, Func<string, string?> problem, TextWriter log) {
        if (!File.Exists(path)) return false;
        if (remake != null) {
            log.WriteLine($"{what}: made again ({remake})");
        } else if (problem(path) is { } why) {
            log.WriteLine($"warning: the cached {what} {path} cannot be used ({Text.Printable(why)}); it is deleted and made again");
        } else {
            return false;
        }
        File.Delete(path);
        return true;
    }

    /// <summary>Ends the run when a profile the analyzer has just written fails its check (<paramref name="problem"/>, null when it passes).</summary>
    static void Fresh(string path, string what, string? problem) {
        if (problem != null)
            throw new AnalyzerException($"the {what} the analyzer just made, {path}, fails the check ({Text.Printable(problem)}); it is not used. "
                + "The analyzer and the pipeline may not match, or the game or libraries may not be what scan expects");
    }

    /// <summary>Runs <c>darkmatter profile</c>, which writes <paramref name="written"/>, and shows its warnings.</summary>
    static void Profile(Settings s, IReadOnlyList<string> args, string written, string what) {
        // A .part kept from an earlier run (one that failed its check) must not pass for this run's output.
        File.Delete(written);
        var (_, stderr) = s.Analyzer.Checked(args, what);
        foreach (var line in stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Console.Error.WriteLine($"  analyzer: {line.TrimEnd('\r')}");
        if (!File.Exists(written)) throw new AnalyzerException($"{what}: the analyzer wrote no {written}");
    }

    /// <summary>The game files a game profile lists as not read ("N files: A, B"), or null when it lists none.</summary>
    static string? Skipped(string profile) {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(profile));
        if (!doc.RootElement.TryGetProperty("skipped", out var sk) || sk.ValueKind != JsonValueKind.Array)
            throw new AnalyzerException($"game profile {profile} has no list of skipped files");
        var files = sk.EnumerateArray().Select(x => x.TryGetProperty("file", out var f) ? f.GetString() ?? "?" : "?").ToList();
        return files.Count == 0 ? null : $"{files.Count} game file{(files.Count == 1 ? "" : "s")}: {string.Join(", ", files.Take(5))}{(files.Count > 5 ? ", ..." : "")}";
    }

    /// <summary>Scans the chosen release of each listing (null version: the newest), reusing results under the same key.</summary>
    static async Task<List<Entry>> ScanReleases(Settings s, Context ctx, List<(Listing Listing, string? Version)> listings, bool updateLatest) {
        var log = Console.Error;
        var entries = new List<Entry>();
        foreach (var (listing, version) in listings) {
            Release? release;
            string? why = null;
            if (version != null) {
                release = listing.Releases.FirstOrDefault(r => r.Version == version)
                    ?? throw new UsageException($"{listing.Id} has no release {Text.Quote(version)}; it has {string.Join(", ", listing.Releases.Select(r => r.Version))}");
                if (release.Yanked) throw new UsageException($"{listing.Id} {version} is yanked: {Text.Printable(release.YankedReason ?? "no reason given")}");
            } else {
                release = Snapshot.Newest(listing);
                if (release == null)
                    why = listing.Releases.Count == 0 ? "no usable release in the snapshot" : "every release is yanked";
            }
            var e = new Entry { Id = listing.Id, Name = listing.Name, Release = release };
            if (release == null) {
                e.Status = "skipped";
                e.Reason = why;
            } else if (!s.Full && LoadResult(s, release) is { } stored && Reusable(stored, ctx, release)) {
                e.Status = "cached";
                e.Result = stored["result"]?.DeepClone();
            }
            entries.Add(e);
        }

        // The result last recorded for each listing, read now: a rescan of the same release
        // overwrites that result file below. Only a run that records its results reads the file.
        var latestPath = s.Dir("latest.json");
        var latest = updateLatest ? LoadLatest(latestPath, log) : [];
        foreach (var e in entries.Where(e => e.Release != null && latest[e.Id] is JsonObject)) {
            var before = (JsonObject)latest[e.Id]!;
            // The sha names a result file: anything but a SHA-256 is not used in a path.
            if (ResultView.Str(before, "sha256") is not { } sha || !Sha256Hex().IsMatch(sha)) {
                log.WriteLine($"warning: {latestPath}: the entry for {e.Id} has no usable sha256; it is ignored, and the listing is reported as new");
                continue;
            }
            e.Before = (JsonObject)before.DeepClone();
            e.BeforeResult = LoadResult(s, e.Id, sha.ToLowerInvariant()) is { } doc && Tiered(doc["result"]) ? doc["result"]!.DeepClone() : null;
        }

        var pending = entries.Where(e => e.Status == "pending").ToList();
        if (pending.Count > 0) log.WriteLine($"scanning {pending.Count} release(s); {entries.Count(e => e.Status == "cached")} unchanged since the last scan");
        foreach (var e in pending) {
            var r = e.Release!;
            if (AssetName(r.Url) is not { } asset) {
                Fail(e, $"its download URL does not end in a usable file name: {r.Url}", log);
                continue;
            }
            // Whatever goes wrong with one listing (reading or hashing its archive, writing its
            // tree, or an error nobody foresaw) fails that listing, not the run.
            try {
                var fetched = await ctx.Store.Get(r, s.MaxBytes);
                if (fetched.Path == null) {
                    Fail(e, fetched.Problem ?? "the archive could not be fetched", log);
                    continue;
                }
                e.Manifest = ExtractCommand.ExtractAssets([(fetched.Path, asset)], e.Id, s.Dir("extracted", e.Id), s.Limits, e.EnvironmentErrors);
                log.WriteLine($"  {e.Id} {Text.Printable(r.Version)}: verified, {e.Manifest.Files.Count} code file(s)");
            } catch (Exception x) when (!Fatal(x)) {
                Fail(e, $"the archive could not be read or extracted: {Describe(x)}", log);
            }
        }
        var ready = pending.Where(e => e.Manifest != null).ToList();
        try {
            Analyze(s, ctx, ready, s.Dir("extracted"));
        } catch (Exception x) when (!Fatal(x)) {
            foreach (var e in ready.Where(e => e.Status == "pending")) Fail(e, $"the analyzer could not be run: {Describe(x)}", log);
        }
        foreach (var e in pending.Where(e => e.Status == "scanned")) {
            try {
                StoreResult(s, ctx, e);
            } catch (Exception x) when (!Fatal(x)) {
                // A result that is not stored is not reported either: the listing fails, and the next run scans it again.
                Fail(e, $"its result could not be stored: {Describe(x)}", log);
            }
        }

        // Changes against the result last recorded for each listing (only when scanning the newest
        // releases: an explicitly chosen older version is not a change of the listing). A release
        // scanned again (a new key, or --full) is compared with its own earlier result.
        foreach (var e in entries.Where(e => e.Result != null && updateLatest)) {
            var r = e.Release!;
            var before = e.Before;
            if (before == null) {
                e.Change = new JsonObject { ["kind"] = "new" };
                continue;
            }
            var sameRelease = string.Equals(ResultView.Str(before, "sha256"), r.Sha256, StringComparison.OrdinalIgnoreCase);
            var diff = e.BeforeResult != null ? ResultDiff.Of(ResultView.From(e.BeforeResult), ResultView.From(e.Result)) : null;
            // No earlier result to compare with (its file is missing or cannot be read) is not "no
            // difference": the change is reported, marked as having nothing to compare with.
            if (sameRelease && diff == null && e.BeforeResult != null) continue;
            e.Change = new JsonObject {
                ["kind"] = sameRelease ? "rescanned" : "updated",
                ["from"] = ResultView.Str(before, "version"),
                ["to"] = r.Version,
                ["difference"] = diff,
            };
            if (e.BeforeResult == null) e.Change["previous"] = "unreadable";
        }
        if (updateLatest) {
            foreach (var e in entries.Where(e => e.Result != null))
                latest[e.Id] = new JsonObject { ["version"] = e.Release!.Version, ["sha256"] = e.Release.Sha256, ["key"] = ctx.Key };
            // A listing that left the snapshot (delisted) is reported once.
            if (listings.Count == ctx.Snapshot.Listings.Count)
                foreach (var gone in latest.Select(kv => kv.Key).Where(id => !ctx.Snapshot.Listings.Any(l => l.Id == id) && !ctx.Snapshot.Rejected.Any(l => l.Id == id)).ToList()) {
                    entries.Add(new Entry { Id = gone, Status = "skipped", Reason = "no longer in the snapshot", Change = new JsonObject { ["kind"] = "gone" } });
                    latest.Remove(gone);
                }
            Text.WriteJson(latestPath, latest);
        }
        return entries;
    }

    /// <summary>A local mod: a folder, a zip or code files, copied or extracted with the archive rules, then analyzed.</summary>
    static Entry ScanLocal(Settings s, Context ctx, List<string> paths, string? name) {
        foreach (var p in paths)
            if (!File.Exists(p) && !Directory.Exists(p)) throw new UsageException($"not found: {p}");
        var first = Path.GetFileName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(paths[0])));
        var id = name ?? (Directory.Exists(paths[0]) ? first : Path.GetFileNameWithoutExtension(first));
        if (!NamePattern().IsMatch(id) || !EntryNames.IsFolderName(id)) id = "mod";
        var dest = s.Dir("local", id);
        var errors = new List<string>();
        ManifestMod manifest;
        if (paths.Count == 1 && Directory.Exists(paths[0])) {
            manifest = ExtractCommand.CopyFolder(paths[0], id, dest, s.Limits, errors);
        } else {
            if (paths.Any(Directory.Exists)) throw new UsageException("give one folder, or files (zips, DLLs), not both");
            manifest = ExtractCommand.ExtractAssets([.. paths.Select(p => (p, Path.GetFileName(p)))], id, dest, s.Limits, errors);
        }
        var identity = new JsonObject {
            ["name"] = id,
            ["paths"] = new JsonArray([.. paths.Select(p => (JsonNode?)JsonValue.Create(p))]),
            ["files"] = new JsonArray([.. manifest.Files.Select(f => (JsonNode?)new JsonObject { ["path"] = Path.GetRelativePath(dest, f.Path).Replace('\\', '/'), ["sha256"] = f.Sha256 })]),
        };
        var e = new Entry { Id = id, Name = id, Identity = identity, Manifest = manifest };
        e.EnvironmentErrors.AddRange(errors);
        Analyze(s, ctx, [e], s.Dir("local"));
        return e;
    }

    /// <summary>Analyzes the entries' extracted trees in one analyzer run; sets each one's result, or marks it failed.</summary>
    static void Analyze(Settings s, Context ctx, List<Entry> entries, string root) {
        if (entries.Count == 0) return;
        Directory.CreateDirectory(s.Work);
        var manifest = Path.Join(s.Work, "manifest.json");
        var results = Path.Join(s.Work, "results.json");
        File.Delete(results);
        Text.WriteJson(manifest, new { root, mods = entries.ToDictionary(e => e.Id, e => e.Manifest!) });
        List<string> args = ["analyze", "--manifest", manifest, "--allowlist", ctx.Allowlist, "--game-profile", ctx.GameProfile, "--json", results];
        if (ctx.LibraryProfile != null) args.AddRange(["--library-profile", ctx.LibraryProfile]);
        Console.Error.WriteLine($"analyzing {entries.Count} mod(s)");
        var (exit, _, stderr) = s.Analyzer.Run(args);
        JsonObject? mods = null;
        if (exit == 0 && File.Exists(results)) mods = JsonNode.Parse(File.ReadAllBytes(results))?["mods"] as JsonObject;
        foreach (var e in entries) {
            try {
                if (mods?[e.Id] is JsonObject r && FilesMismatch(r, e.Manifest!) is { } mismatch) {
                    e.Status = "failed";
                    e.Reason = $"the analyzer's result does not match the files extracted for this release ({mismatch}); not stored";
                } else if (mods?[e.Id] is JsonObject r2) {
                    _ = ResultView.From(r2);  // a result with a tier, or the listing fails
                    e.Status = "scanned";
                    e.Result = r2.DeepClone();
                    e.Retry = RetryReason(e, r2) ?? ctx.Incomplete;
                } else {
                    e.Status = "failed";
                    e.Reason = $"the analyzer failed (exit {exit}): {string.Join(" / ", stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).TakeLast(3))}"
                        + (exit != 0 && ctx.ProfileReused ? "; a game or library profile kept from an earlier run was used: if the analyzer rejects it, run again with --full to make it again" : "");
                }
            } catch (Exception x) when (!Fatal(x)) {
                Fail(e, $"the analyzer's result cannot be read: {Describe(x)}", Console.Error);
            }
        }
        // Warnings the analyzer prints are about the inputs (profiles, allowlist), not about a mod.
        foreach (var line in stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries)) Console.Error.WriteLine($"  analyzer: {line}");
    }

    /// <summary>
    /// Whether a stored result stands for the release under this run's stamp: the same key, the same
    /// name the archive is extracted under (it is part of every file path in the result), not marked
    /// to be retried, and a result that can be read, with a tier. Anything else is scanned again.
    /// </summary>
    static bool Reusable(JsonObject stored, Context ctx, Release r) =>
        ResultView.Str(stored["stamp"] as JsonObject, "key") == ctx.Key
        && AssetName(r.Url) is { } asset && ResultView.Str(stored["release"] as JsonObject, "url") is { } url && AssetName(url) == asset
        && stored["retry"] == null
        && Tiered(stored["result"]);

    /// <summary>Whether <paramref name="result"/> reads as a result (<see cref="ResultView.From"/>), with a tier.</summary>
    static bool Tiered(JsonNode? result) {
        try {
            _ = ResultView.From(result);
            return true;
        } catch (InvalidDataException) {
            return false;
        }
    }

    /// <summary>Errors a listing's own failure must not hide: the process cannot go on after them.</summary>
    static bool Fatal(Exception x) => x is OutOfMemoryException;

    /// <summary>An exception's type and message, for a listing's failure reason.</summary>
    static string Describe(Exception x) => $"{x.GetType().Name}: {x.Message}";

    /// <summary>Marks a listing failed: nothing of it is analyzed, stored or reported as a result.</summary>
    static void Fail(Entry e, string reason, TextWriter log) {
        e.Status = "failed";
        e.Reason = reason;
        e.Manifest = null;
        e.Result = null;
        e.Retry = null;
        log.WriteLine($"  {e.Id} {Text.Printable(e.Release?.Version ?? "")}: {Text.Printable(reason)}");
    }

    /// <summary>
    /// latest.json: the release and key last recorded for each listing. One that cannot be read as
    /// an object is moved aside (<c>latest.json.damaged-TIME</c>), with a warning, and the run
    /// starts with no recorded results: every listing is then reported as new.
    /// </summary>
    static JsonObject LoadLatest(string path, TextWriter log) {
        if (!File.Exists(path)) return [];
        string problem;
        try {
            if (Text.ParseStored(File.ReadAllBytes(path)) is JsonObject latest) return latest;
            problem = "not a JSON object";
        } catch (Exception x) when (x is JsonException or ArgumentException) {
            problem = x.Message;
        }
        var aside = $"{path}.damaged-{DateTimeOffset.UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture)}";
        File.Move(path, aside);
        log.WriteLine($"warning: {path} cannot be read ({problem}); moved to {aside}. This run starts with no recorded results, so every listing is reported as new");
        return [];
    }

    /// <summary>Why a result does not belong to the manifest it was meant for (its files are not the extracted ones); null when it does.</summary>
    static string? FilesMismatch(JsonObject result, ManifestMod manifest) {
        var files = (result["files"] as JsonArray ?? []).OfType<JsonObject>().ToList();
        if (files.Count != manifest.Files.Count) return $"{files.Count} files, not {manifest.Files.Count}";
        var want = manifest.Files.Select(f => f.Sha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var other = files.Select(f => ResultView.Str(f, "sha256")).FirstOrDefault(h => h != null && !want.Contains(h));
        return other != null ? $"a file with SHA-256 {other[..Math.Min(12, other.Length)]}... was not extracted" : null;
    }

    /// <summary>
    /// Why a result may come from a passing problem of this computer rather than from the release:
    /// a file-system error while extracting, a file the analyzer could not read, or a file that
    /// changed between extraction and analysis. Such a result is reported (it fails closed, as Broad
    /// access) but the next run scans the release again instead of reusing it. Null when none.
    /// </summary>
    static string? RetryReason(Entry e, JsonObject result) {
        if (e.EnvironmentErrors.Count > 0) return "extraction failed: " + e.EnvironmentErrors[0];
        foreach (var (_, reason) in ResultView.From(result).Reasons) {
            if (reason.Id == "not-analyzed") return "a file changed between extraction and analysis";
            if (reason.Id == "unreadable-file" && reason.Evidence.FirstOrDefault(x => x.Contains(": file could not be read", StringComparison.Ordinal)) is { } read)
                return "a file could not be read: " + read;
        }
        return null;
    }

    static string ResultPath(Settings s, string id, string sha) => s.Dir("results", id, sha + ".json");

    static JsonObject? LoadResult(Settings s, Release r) => LoadResult(s, r.Id, r.Sha256);

    /// <summary>A stored result document, or null when there is none or it cannot be read (the release is then scanned again).</summary>
    static JsonObject? LoadResult(Settings s, string id, string sha) {
        var path = ResultPath(s, id, sha);
        try {
            return File.Exists(path) ? Text.ParseStored(File.ReadAllBytes(path)) as JsonObject : null;
        } catch (Exception x) when (x is IOException or UnauthorizedAccessException or JsonException or ArgumentException) {
            Console.Error.WriteLine($"warning: the stored result {path} cannot be read ({x.Message}); it is not used");
            return null;
        }
    }

    /// <summary>Writes the result document of a scanned release: what was scanned, under which stamp, and the analyzer's result.</summary>
    static void StoreResult(Settings s, Context ctx, Entry e) {
        var path = ResultPath(s, e.Id, e.Release!.Sha256);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        Text.WriteJson(path, new JsonObject {
            ["schema"] = Schema,
            ["kind"] = "result",
            ["release"] = ReleaseJson(e.Release, e.Name),
            ["stamp"] = ctx.Stamp.DeepClone(),
            ["snapshot"] = SnapshotJson(ctx.Snapshot),
            ["scannedAt"] = Now(),
            ["retry"] = e.Retry,
            ["result"] = e.Result!.DeepClone(),
        });
    }

    static JsonObject ReleaseJson(Release r, string name) => new() {
        ["id"] = r.Id,
        ["name"] = name,
        ["version"] = r.Version,
        ["sha256"] = r.Sha256,
        ["status"] = r.Status,
        ["releaseDate"] = r.Date,
        ["url"] = r.Url,
        ["loader"] = r.Loader,
        ["gameMin"] = r.GameMin,
        ["gameMax"] = r.GameMax,
    };

    static JsonObject SnapshotJson(Snapshot s) {
        var o = new JsonObject {
            ["source"] = s.Source,
            ["sha256"] = s.Sha256,
            ["sources"] = s.Sources?.DeepClone(),
        };
        // A kept copy used because the download failed: present only then.
        if (s.Stale != null) o["stale"] = s.Stale;
        return o;
    }

    static string Now() => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>The run document: what was scanned, under which stamp, every entry with its result, and the changes.</summary>
    static JsonObject RunDocument(string mode, bool local, DateTimeOffset started, Context ctx, List<Entry> entries) {
        var tiers = new JsonObject();
        foreach (var t in entries.Where(e => e.Result != null).GroupBy(e => ResultView.From(e.Result).Tier).OrderBy(g => g.Key, StringComparer.Ordinal))
            tiers[t.Key] = t.Count();
        var releases = new JsonArray();
        foreach (var e in entries.OrderBy(e => e.Id, StringComparer.Ordinal)) {
            var o = new JsonObject {
                ["id"] = e.Id,
                ["name"] = e.Name,
                ["status"] = e.Status,
            };
            if (e.Release != null) o["release"] = ReleaseJson(e.Release, e.Name);
            if (e.Identity != null) o["local"] = e.Identity.DeepClone();
            if (e.Reason != null) o["reason"] = e.Reason;
            if (e.Retry != null) o["retry"] = e.Retry;
            if (e.Change != null) o["change"] = e.Change.DeepClone();
            if (e.Result != null) o["result"] = e.Result.DeepClone();
            releases.Add(o);
        }
        return new JsonObject {
            ["schema"] = Schema,
            ["kind"] = "run",
            ["mode"] = local ? "mod (local files)" : mode,
            ["startedAt"] = started.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ["finishedAt"] = Now(),
            ["stamp"] = ctx.Stamp.DeepClone(),
            ["snapshot"] = SnapshotJson(ctx.Snapshot),
            ["summary"] = new JsonObject {
                ["listings"] = entries.Count,
                ["scanned"] = entries.Count(e => e.Status == "scanned"),
                ["cached"] = entries.Count(e => e.Status == "cached"),
                ["skipped"] = entries.Count(e => e.Status == "skipped"),
                ["failed"] = entries.Count(e => e.Status == "failed"),
                ["changed"] = entries.Count(e => e.Change != null),
                ["tiers"] = tiers,
            },
            ["releases"] = releases,
        };
    }

    /// <summary>
    /// The name a release's archive is extracted under: the last part of its download URL, as the
    /// player's download is named. Null (the release is not scanned) when that is not exactly one
    /// usable file name as it is: empty, a trailing "/" or an encoded one ("%2F"), a leading dot, or
    /// a name <see cref="EntryNames"/> refuses or renames.
    /// </summary>
    static string? AssetName(string url) {
        var segment = Uri.TryCreate(url, UriKind.Absolute, out var u) ? Uri.UnescapeDataString(u.Segments.LastOrDefault() ?? "") : "";
        return segment.Length > 0 && !segment.StartsWith('.') && EntryNames.Check(segment, directory: false, out var parts) == null
            && parts.Length == 1 && parts[0] == segment
            ? segment
            : null;
    }

    static string Sha(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
}

/// <summary>Another scan holds the state directory's lock.</summary>
internal sealed class StateBusyException(string message) : Exception(message);
