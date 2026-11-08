// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DarkMatter;

/// <summary>Access tier of a mod, lowest first.</summary>
internal enum Tier { ContentOnly, KnownAccess, Unverified, FullAccess }

/// <summary>Whether a file operation reads or writes.</summary>
internal enum FileOpKind { Read, Write }

internal static class TierExtensions {
    /// <summary>The tier's identifier in the policy and in JSON output ("full-access").</summary>
    public static string Id(this Tier tier) => tier switch {
        Tier.ContentOnly => "content-only",
        Tier.KnownAccess => "known-access",
        Tier.Unverified => "unverified",
        _ => "full-access",
    };
}

/// <summary>
/// The detection and tier policy, loaded from policy/policy.jsonc (embedded at build time,
/// or a file passed with --policy). See that file for the meaning of each section.
/// </summary>
internal sealed class Policy {
    /// <summary>Capabilities the analyzer produces itself rather than from a rule.</summary>
    public static readonly IReadOnlyList<string> Derived = [
        "shell-open", "shell-open-folder", "file-saves", "file-write-outside", "file-read-outside", "file-write-code",
    ];

    /// <summary>Findings that are not capabilities; each needs a "fullAccess" or an "unverified" entry.</summary>
    public static readonly IReadOnlyList<string> Findings = [
        "unresolved-reflection", "bounded-reflection", "com-activation", "decode-failure", "unreadable-file",
        "native-binary", "unextracted-archive", "not-analyzed", "unclassified-reference", "unanalyzed-call",
        "ships-script", "embedded-binary", "name-collision", "rewrite-outside-game",
    ];

    /// <summary>The pseudo-capability of a "safe" rule: the member needs no capability.</summary>
    public const string Safe = "safe";

    const string EmbeddedName = "policy.jsonc";
    static readonly char[] TypeNameTerminators = [',', '[', ':'];

    public required string Version { get; init; }
    public required string Sha256 { get; init; }
    public required IReadOnlyDictionary<string, string> Tiers { get; init; }
    public required IReadOnlyList<Rule> Rules { get; init; }
    public required IReadOnlyDictionary<string, string> FullAccess { get; init; }
    public required IReadOnlyDictionary<string, string> Unverified { get; init; }
    public required IReadOnlyList<Combination> Combinations { get; init; }
    public required IReadOnlyList<Label> Labels { get; init; }
    public required IReadOnlySet<string> Informational { get; init; }
    public required IReadOnlyDictionary<string, FileOpKind> FileKinds { get; init; }
    public required IReadOnlySet<string> InsideOrigins { get; init; }
    public required IReadOnlySet<string> CodeOrigins { get; init; }
    public required IReadOnlyDictionary<string, string> PathSources { get; init; }
    public required IReadOnlyList<Rule> UrlLoads { get; init; }
    public required int DocumentsFolder { get; init; }
    public required Regex GameFolderLiteral { get; init; }
    public required Regex AbsolutePathLiteral { get; init; }
    public required IReadOnlyList<string> GameAssemblies { get; init; }
    public required IReadOnlyList<Exemption> GameExempt { get; init; }
    public required IReadOnlyList<Exemption> LibraryExempt { get; init; }

    readonly ConcurrentDictionary<string, Classification> cache = new(StringComparer.Ordinal);

    internal sealed record Label(string Text, IReadOnlySet<string> Caps);

    /// <summary>A Full-access finding for a mod that has all of <see cref="Caps"/>.</summary>
    internal sealed record Combination(string Id, string Text, IReadOnlyList<string> Caps);

    internal enum MatchKind { Prefix, Exact, Contains }

    /// <summary>
    /// Game or trusted-library members that neither have nor pass on the listed capabilities:
    /// a capability that raises the tier and is the member's intended job and is accounted for another
    /// way, or a capability the check over-approximates there (for example reflection by a
    /// constant member name, which grants the whole type's capabilities). Applied while a
    /// profile is built: the capability is dropped where it is found in a matching member, and
    /// does not flow from a matching member to its callers (or to a mod calling it).
    /// </summary>
    /// <param name="Library">Allowlist name of the library ("0Harmony"); null for the game.</param>
    /// <param name="Pattern">Member pattern, same syntax as a capability rule (no parameter list or arity).</param>
    /// <param name="Caps">Capabilities or findings that are not passed on.</param>
    /// <param name="As">A label capability passed on instead, or null.</param>
    /// <param name="Reason">Why, for the reader of the policy.</param>
    internal sealed record Exemption(string? Library, Rule Pattern, IReadOnlySet<string> Caps, string? As, string Reason);

    /// <summary>The outcome of matching a member against every rule.</summary>
    /// <param name="Matched">A capability or safe rule matched; false means the policy says nothing about the member.</param>
    /// <param name="Caps">Capabilities of the most specific matching rules (empty when safe).</param>
    internal sealed record Classification(bool Matched, IReadOnlyList<string> Caps) {
        public static readonly Classification None = new(false, []);
    }

    internal sealed record Rule(string Cap, MatchKind Kind, string Text, int Arity, IReadOnlyList<string>? Params, bool ParamsPrefix) {
        /// <summary>Specificity: the longest matching pattern wins. A parameter list makes a rule more specific.</summary>
        public int Length => Text.Length + (Params == null ? 0 : 1 + Params.Sum(p => p.Length + 1));

        public static Rule Parse(string cap, string pattern) {
            int arity = -1;
            List<string>? ps = null;
            bool psPrefix = false;
            int open = pattern.IndexOf('(', StringComparison.Ordinal);
            if (open > 0) {
                if (!pattern.EndsWith(')')) throw new InvalidDataException($"invalid policy: pattern '{pattern}' has an unclosed parameter list");
                var inner = pattern[(open + 1)..^1];
                ps = inner.Length == 0 ? [] : [.. inner.Split(',').Select(p => p.Trim())];
                if (ps.Count > 0 && ps[^1] == "...") { psPrefix = true; ps.RemoveAt(ps.Count - 1); }
                pattern = pattern[..open];
                // A parameter list names one member exactly: "Load(System.String)" must not match "LoadXml".
                return new(cap, MatchKind.Exact, pattern.TrimEnd('$'), -1, ps, psPrefix);
            }
            int hash = pattern.LastIndexOf('#');
            if (hash > 0 && int.TryParse(pattern.AsSpan(hash + 1), out var n)) { arity = n; pattern = pattern[..hash]; }
            if (pattern.StartsWith("::", StringComparison.Ordinal)) return new(cap, MatchKind.Contains, pattern, arity, null, false);
            if (pattern.EndsWith('$')) return new(cap, MatchKind.Exact, pattern[..^1], arity, null, false);
            return new(cap, MatchKind.Prefix, pattern, arity, null, false);
        }

        /// <param name="member">"Namespace.Type::Member".</param>
        /// <param name="ps">Parameter types of the referenced method, or null if unknown or not a method.</param>
        public bool Matches(string member, IReadOnlyList<string>? ps) {
            if (Arity >= 0 && ps != null && Arity != ps.Count) return false;
            if (Params != null) {
                if (ps == null) return false;
                if (ParamsPrefix ? ps.Count < Params.Count : ps.Count != Params.Count) return false;
                for (int i = 0; i < Params.Count; i++) if (Params[i] != ps[i]) return false;
            }
            return Kind switch {
                MatchKind.Contains => member.Contains(Text, StringComparison.Ordinal),
                MatchKind.Exact => member == Text,
                _ => member.StartsWith(Text, StringComparison.Ordinal),
            };
        }
    }

    /// <summary>The embedded default policy text.</summary>
    public static string EmbeddedText() {
        using var s = OpenEmbedded(EmbeddedName);
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    /// <summary>An embedded resource of the tool, or null if there is none by that name.</summary>
    public static Stream? OpenResource(string name) => Assembly.GetExecutingAssembly().GetManifestResourceStream(name);

    static Stream OpenEmbedded(string name) => OpenResource(name) ?? throw new InvalidOperationException($"embedded {name} missing");

    static readonly JsonDocumentOptions JsoncOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>Loads a policy file, or the embedded default when <paramref name="path"/> is null.</summary>
    public static Policy Load(string? path) {
        byte[] bytes;
        if (path != null) {
            bytes = File.ReadAllBytes(path);
        } else {
            using var s = OpenEmbedded(EmbeddedName);
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            bytes = ms.ToArray();
        }
        using var doc = JsonDocument.Parse(bytes, JsoncOptions);
        var root = doc.RootElement;
        var fa = root.GetProperty("fileAccess");
        var game = root.GetProperty("game");

        var rules = new List<Rule>();
        foreach (var c in root.GetProperty("capabilities").EnumerateObject())
            foreach (var p in c.Value.EnumerateArray()) rules.Add(Rule.Parse(c.Name, Text(p)));
        foreach (var p in root.GetProperty("safe").EnumerateArray()) rules.Add(Rule.Parse(Safe, Text(p)));

        var policy = new Policy {
            Version = Text(root.GetProperty("version")),
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Tiers = Strings(root.GetProperty("tiers")),
            Rules = rules,
            FullAccess = Strings(root.GetProperty("fullAccess")),
            Unverified = Strings(root.GetProperty("unverified")),
            Combinations = [.. root.GetProperty("fullAccessCombinations").EnumerateArray()
                .Select(c => new Combination(Text(c.GetProperty("id")), Text(c.GetProperty("text")), [.. c.GetProperty("caps").EnumerateArray().Select(Text)]))],
            Labels = [.. root.GetProperty("labels").EnumerateArray().Select(l => new Label(Text(l.GetProperty("text")), Set(l.GetProperty("caps"))))],
            Informational = Set(root.GetProperty("informational")),
            FileKinds = Strings(fa.GetProperty("kinds")).ToDictionary(kv => kv.Key, kv => kv.Value switch {
                "read" => FileOpKind.Read,
                "write" => FileOpKind.Write,
                _ => throw new InvalidDataException($"invalid policy: fileAccess.kinds value '{kv.Value}' must be read or write"),
            }),
            InsideOrigins = Set(fa.GetProperty("inside")),
            CodeOrigins = Set(fa.GetProperty("code")),
            PathSources = Strings(fa.GetProperty("sources")),
            UrlLoads = [.. fa.GetProperty("urls").EnumerateArray().Select(u => Rule.Parse("url", Text(u)))],
            DocumentsFolder = fa.GetProperty("documentsFolder").GetInt32(),
            GameFolderLiteral = new Regex(Text(fa.GetProperty("gameFolderLiteral")), RegexOptions.IgnoreCase),
            AbsolutePathLiteral = new Regex(Text(fa.GetProperty("absolutePathLiteral"))),
            GameAssemblies = [.. game.GetProperty("assemblies").EnumerateArray().Select(Text)],
            GameExempt = Exemptions(game.GetProperty("exempt"), false),
            LibraryExempt = Exemptions(root.GetProperty("libraries").GetProperty("exempt"), true),
        };
        policy.Validate();
        return policy;
    }

    static string Text(JsonElement e) => e.GetString() ?? throw new InvalidDataException("invalid policy: null where text was expected");
    static Dictionary<string, string> Strings(JsonElement e) => e.EnumerateObject().ToDictionary(p => p.Name, p => Text(p.Value));
    static HashSet<string> Set(JsonElement e) => [.. e.EnumerateArray().Select(Text)];

    // An exemption names one member pattern ("member") or several that share its capabilities and
    // reason ("members").
    static List<Exemption> Exemptions(JsonElement e, bool library) => [.. e.EnumerateArray().SelectMany(x =>
        (x.TryGetProperty("members", out var many) ? many.EnumerateArray().Select(Text) : [Text(x.GetProperty("member"))])
            .Select(member => new Exemption(
                library ? Text(x.GetProperty("library")) : null,
                Rule.Parse("exempt", member),
                Set(x.GetProperty("caps")),
                x.TryGetProperty("as", out var instead) ? Text(instead) : null,
                Text(x.GetProperty("reason")))))];

    /// <summary>
    /// Whether a capability or finding raises the tier on its own: Full access or Unverified.
    /// What a game or library member passes on through overrides and patches is decided by this.
    /// </summary>
    public bool RaisesTier(string cap) => FullAccess.ContainsKey(cap) || Unverified.ContainsKey(cap);

    /// <summary>The tier a capability or finding puts a mod in on its own, or null for none.</summary>
    public Tier? TierOf(string cap) => FullAccess.ContainsKey(cap) ? Tier.FullAccess : Unverified.ContainsKey(cap) ? Tier.Unverified : null;

    /// <summary>Every capability the analyzer can produce.</summary>
    public IEnumerable<string> ProducibleCaps => Rules.Where(r => r.Cap != Safe).Select(r => r.Cap)
        .Concat(Derived).Distinct();

    void Validate() {
        var errors = new List<string>();
        var labelled = Labels.SelectMany(l => l.Caps).ToHashSet();
        foreach (var cap in ProducibleCaps) {
            int homes = (FullAccess.ContainsKey(cap) ? 1 : 0) + (Unverified.ContainsKey(cap) ? 1 : 0) + (labelled.Contains(cap) ? 1 : 0)
                + (FileKinds.ContainsKey(cap) ? 1 : 0) + (Informational.Contains(cap) ? 1 : 0);
            if (homes != 1) errors.Add($"capability '{cap}' must appear in exactly one of fullAccess, unverified, labels, fileAccess.kinds, informational (found {homes})");
        }
        var producible = ProducibleCaps.ToHashSet();
        foreach (var (section, entries) in new[] { ("fullAccess", FullAccess), ("unverified", Unverified) })
            foreach (var (key, text) in entries) {
                if (!producible.Contains(key) && !Findings.Contains(key)) errors.Add($"{section} entry '{key}' is neither a capability nor a finding");
                if (string.IsNullOrWhiteSpace(text)) errors.Add($"{section} entry '{key}' has no text");
            }
        foreach (var f in Findings) {
            int homes = (FullAccess.ContainsKey(f) ? 1 : 0) + (Unverified.ContainsKey(f) ? 1 : 0);
            if (homes != 1) errors.Add($"finding '{f}' must appear in exactly one of fullAccess, unverified (found {homes})");
        }
        // Each reason is shown to the user on its own: two that read the same cannot be told apart.
        foreach (var text in FullAccess.Values.Concat(Unverified.Values).GroupBy(t => t, StringComparer.Ordinal).Where(g => g.Count() > 1))
            errors.Add($"the reason text '{text.Key}' is used more than once in fullAccess and unverified");
        foreach (var cap in labelled.Concat(Informational).Concat(FileKinds.Keys))
            if (!producible.Contains(cap)) errors.Add($"'{cap}' is referenced but no rule produces it");
        foreach (var c in Combinations) {
            if (RaisesTier(c.Id) || Combinations.Count(x => x.Id == c.Id) > 1) errors.Add($"fullAccessCombinations id '{c.Id}' is not unique");
            if (string.IsNullOrWhiteSpace(c.Text) || FullAccess.Values.Contains(c.Text) || Unverified.Values.Contains(c.Text) || Combinations.Count(x => x.Text == c.Text) > 1)
                errors.Add($"fullAccessCombinations '{c.Id}' needs a text of its own");
            if (c.Caps.Count < 2 || c.Caps.Distinct().Count() != c.Caps.Count) errors.Add($"fullAccessCombinations '{c.Id}' needs at least two different capabilities");
            foreach (var cap in c.Caps) {
                if (!producible.Contains(cap)) errors.Add($"fullAccessCombinations '{c.Id}' references '{cap}', which no rule produces");
                // A Full-access or Unverified capability decides the tier on its own; a combination
                // is made of capabilities that are Known access one by one.
                else if (TierOf(cap) is { } t) errors.Add($"fullAccessCombinations '{c.Id}' references '{cap}', which is {Tiers.GetValueOrDefault(t.Id(), t.Id())} on its own");
            }
        }
        foreach (var o in CodeOrigins)
            if (!InsideOrigins.Contains(o)) errors.Add($"fileAccess.code origin '{o}' must also be an inside origin");
        // A web address is fetched with the network: the label must exist for it.
        if (UrlLoads.Count > 0 && !labelled.Contains("network")) errors.Add("fileAccess.urls needs the network capability in a label");
        foreach (var r in Rules.Where(r => r.Cap == Safe && r.Kind == MatchKind.Contains))
            errors.Add($"safe pattern '{r.Text}' matches members of any type; name the type");
        foreach (var x in GameExempt.Concat(LibraryExempt)) {
            string what = $"exemption '{(x.Library != null ? x.Library + ": " : "")}{x.Pattern.Text}'";
            if (x.Pattern.Params != null || x.Pattern.Arity >= 0) errors.Add($"{what} cannot use a parameter list or arity: profiles merge overloads");
            if (x.Caps.Count == 0) errors.Add($"{what} lists no capabilities");
            foreach (var cap in x.Caps)
                if (!RaisesTier(cap) && !labelled.Contains(cap)) errors.Add($"{what} lists '{cap}', which is not a Full-access or Unverified capability, finding or label capability");
            if (x.Library == null && x.Caps.Any(Findings.Contains)) errors.Add($"{what} lists a finding; game profiles carry capabilities only");
            if (x.As != null && !labelled.Contains(x.As)) errors.Add($"{what} passes on '{x.As}' instead, which is not a label capability");
            if (string.IsNullOrWhiteSpace(x.Reason)) errors.Add($"{what} gives no reason");
        }
        foreach (var t in Enum.GetValues<Tier>())
            if (!Tiers.ContainsKey(t.Id())) errors.Add($"tiers has no name for '{t.Id()}'");
        foreach (var id in Tiers.Keys)
            if (!Enum.GetValues<Tier>().Any(t => t.Id() == id)) errors.Add($"tiers names '{id}', which is not a tier");
        if (errors.Count > 0) throw new InvalidDataException("invalid policy:\n  " + string.Join("\n  ", errors));
    }

    /// <summary>
    /// Classifies a referenced member ("Namespace.Type::Member"). Every matching rule is
    /// considered and the most specific (longest) pattern wins, so "Marshal::SizeOf" can be safe
    /// while the rest of "Marshal::" is raw memory. Rules of equal specificity all apply.
    /// </summary>
    /// <param name="member">"Namespace.Type::Member".</param>
    /// <param name="ps">Parameter types of the referenced method, or null if not a method.</param>
    public Classification Classify(string member, IReadOnlyList<string>? ps = null) {
        string key = ps == null ? member : member + "(" + string.Join(",", ps) + ")";
        return cache.GetOrAdd(key, _ => {
            int best = -1;
            var caps = new List<string>();
            foreach (var r in Rules) {
                if (!r.Matches(member, ps)) continue;
                int len = r.Length;
                if (len > best) { best = len; caps.Clear(); }
                if (len == best && r.Cap != Safe && !caps.Contains(r.Cap)) caps.Add(r.Cap);
            }
            return best < 0 ? Classification.None : new Classification(true, caps);
        });
    }

    /// <summary>
    /// Capabilities reachable through a type obtained by reflection: those of the type, its
    /// namespace, and every one of its members, since a reflective caller can pick any member.
    /// </summary>
    public IEnumerable<string> CapsOfType(string typeName) {
        var type = NormalizeTypeName(typeName);
        if (type.Length == 0) yield break;
        var seen = new HashSet<string>();
        foreach (var r in Rules) {
            if (r.Kind == MatchKind.Contains || r.Cap == Safe) continue;
            bool hit = type.StartsWith(r.Text, StringComparison.Ordinal)
                || r.Text.StartsWith(type + "::", StringComparison.Ordinal)
                || r.Text.StartsWith(type + "/", StringComparison.Ordinal);
            if (hit && seen.Add(r.Cap)) yield return r.Cap;
        }
    }

    /// <summary>Whether a file operation also takes a web address in place of its path (<c>fileAccess.urls</c>).</summary>
    public bool MayBeUrl(string member, IReadOnlyList<string>? ps) => UrlLoads.Any(r => r.Matches(member, ps));

    /// <summary>
    /// Whether any capability or safe rule names <paramref name="type"/>, one of its members, or a
    /// namespace or type prefix it falls under: the policy knows it as a framework type.
    /// </summary>
    public bool TouchesType(string type) => Rules.Any(r => r.Kind != MatchKind.Contains
        && (r.Text.StartsWith(type + "::", StringComparison.Ordinal) || r.Text.StartsWith(type + "/", StringComparison.Ordinal)
            || (r.Kind == MatchKind.Prefix && (type + "::").StartsWith(r.Text, StringComparison.Ordinal))));

    /// <summary>
    /// Whether the rules classify what reflection on <paramref name="type"/> can reach: one of
    /// <paramref name="members"/> (the accessors of one property or event), or with null, every
    /// member, which needs a rule whose prefix covers the whole type.
    /// </summary>
    public bool Covers(string type, IReadOnlyList<string>? members) =>
        members != null
            ? members.Any(m => Classify(type + "::" + m).Matched)
            : Rules.Any(r => r.Kind == MatchKind.Prefix && r.Params == null && r.Arity < 0 && (type + "::").StartsWith(r.Text, StringComparison.Ordinal));

    /// <summary>
    /// The exemption that stops <paramref name="cap"/> at a game member (<paramref name="library"/>
    /// null) or a member of a trusted library, or null if it passes.
    /// </summary>
    /// <param name="library">Allowlist name of the library, or null for the game.</param>
    /// <param name="member">"Namespace.Type::Member".</param>
    /// <param name="cap">A capability or finding.</param>
    public Exemption? ExemptionFor(string? library, string member, string cap) =>
        (library == null ? GameExempt : LibraryExempt).FirstOrDefault(x =>
            x.Caps.Contains(cap) && string.Equals(x.Library, library, StringComparison.OrdinalIgnoreCase) && x.Pattern.Matches(member, null));

    /// <summary>Whether an assembly name is one of the policy's fallback game assemblies ("Brutal.*" matches by prefix).</summary>
    public static bool MatchesName(IEnumerable<string> patterns, string name) =>
        patterns.Any(p => p.EndsWith('*') ? name.StartsWith(p[..^1], StringComparison.OrdinalIgnoreCase) : string.Equals(p, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Reduces a reflection type string to "Namespace.Type": drops the assembly qualifier,
    /// generic arguments and Harmony's ":Member" suffix, and writes nested types with '/'.
    /// </summary>
    public static string NormalizeTypeName(string s) {
        if (string.IsNullOrWhiteSpace(s)) return "";
        s = s.Trim();
        int cut = s.IndexOfAny(TypeNameTerminators);
        if (cut >= 0) s = s[..cut];
        return s.Trim().Replace('+', '/');
    }
}
