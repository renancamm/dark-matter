// SPDX-License-Identifier: MIT
using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DarkMatter;

/// <summary>Access tier of a mod, lowest first.</summary>
internal enum Tier { NoCode, LimitedAccess, BroadAccess }

/// <summary>Whether a file operation reads or writes.</summary>
internal enum FileOpKind { Read, Write }

internal static class TierExtensions {
    /// <summary>The tier's identifier in the policy and in JSON output ("broad-access").</summary>
    public static string Id(this Tier tier) => tier switch {
        Tier.NoCode => "no-code",
        Tier.LimitedAccess => "limited-access",
        _ => "broad-access",
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
        // An XmlSerializer whose type is not fixed where it is made; and what the game's exemption passes
        // on for one, kept at a mod's call only where the mod chooses the type.
        "xml-serialization-open", "xml-serialization-game",
        // The unsafe compile flag on its own (informational; the IL walk finds every unsafe construct).
        "unsafe-code",
    ];

    /// <summary>Findings that are not capabilities; each needs an entry in one "broadAccess" group.</summary>
    public static readonly IReadOnlyList<string> Findings = [
        "unresolved-reflection", "bounded-reflection", "com-activation", "decode-failure", "unreadable-file",
        "native-binary", "unextracted-archive", "not-analyzed", "unclassified-reference", "unanalyzed-call",
        "ships-script", "embedded-binary", "name-collision", "rewrite-outside-game", "missing-game-code",
    ];

    /// <summary>The pseudo-capability of a "safe" rule: the member needs no capability.</summary>
    public const string Safe = "safe";

    const string EmbeddedName = "policy.jsonc";
    static readonly char[] TypeNameTerminators = [',', '[', ':'];

    public required string Version { get; init; }
    public required string Sha256 { get; init; }
    public required IReadOnlyDictionary<string, TierText> Tiers { get; init; }
    public required IReadOnlyList<Rule> Rules { get; init; }
    /// <summary>The Broad-access reason groups, in display order.</summary>
    public required IReadOnlyList<Group> Groups { get; init; }
    /// <summary>Every Broad-access capability or finding, with its reason text (all groups).</summary>
    public required IReadOnlyDictionary<string, string> BroadAccess { get; init; }
    public required IReadOnlyList<Combination> Combinations { get; init; }
    public required IReadOnlyList<Label> Labels { get; init; }
    public required IReadOnlySet<string> Informational { get; init; }
    public required IReadOnlyDictionary<string, FileOpKind> FileKinds { get; init; }
    public required IReadOnlySet<string> InsideOrigins { get; init; }
    public required IReadOnlySet<string> CodeOrigins { get; init; }
    public required IReadOnlyDictionary<string, string> PathSources { get; init; }
    public required IReadOnlyList<Rule> UrlLoads { get; init; }
    public required int DocumentsFolder { get; init; }
    /// <summary>What follows the Documents folder in a path to the game's folder (case-sensitive).</summary>
    public required Regex GameFolder { get; init; }
    public required Regex AbsolutePathLiteral { get; init; }
    public required IReadOnlyList<string> GameAssemblies { get; init; }
    public required IReadOnlyList<Exemption> GameExempt { get; init; }
    public required IReadOnlyList<Exemption> LibraryExempt { get; init; }

    readonly ConcurrentDictionary<string, Classification> cache = new(StringComparer.Ordinal);

    /// <summary>A label: its stable id (what results are keyed by), the text shown to the user, and the capabilities that give it.</summary>
    internal sealed record Label(string Id, string Text, IReadOnlySet<string> Caps);

    /// <summary>A tier's name and one-line summary, shown to the user.</summary>
    internal sealed record TierText(string Name, string Summary);

    /// <summary>A group of Broad-access reasons: why a mod is Broad access, for the user.</summary>
    /// <param name="Id">Identifier in the policy and in JSON output ("system-access").</param>
    /// <param name="Name">Shown to the user ("System access").</param>
    /// <param name="Summary">One line shown to the user.</param>
    /// <param name="Reasons">Capability or finding -> reason text.</param>
    internal sealed record Group(string Id, string Name, string Summary, IReadOnlyDictionary<string, string> Reasons);

    /// <summary>A Broad-access finding, in group <see cref="Group"/>, for a mod that has all of <see cref="Caps"/>.</summary>
    internal sealed record Combination(string Id, string Group, string Text, IReadOnlyList<string> Caps);

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
    /// <param name="As">A label capability passed on instead (or a Broad-access one the mod's call narrows), or null.</param>
    /// <param name="Reason">Why, for the reader of the policy.</param>
    /// <param name="AtCall">What is exempted is accounted for at the mod's direct call to the member (its
    /// arguments are traced there): reached any other way (a delegate, a method handle, reflection, a
    /// patch), the member is unresolved reflection at the mod.</param>
    internal sealed record Exemption(string? Library, Rule Pattern, IReadOnlySet<string> Caps, string? As, string Reason, bool AtCall = false);

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

        var groups = root.GetProperty("broadAccess").EnumerateObject()
            .Select(g => new Group(g.Name, Text(g.Value.GetProperty("name")), Text(g.Value.GetProperty("summary")), Strings(g.Value.GetProperty("reasons")))).ToList();
        // A key in two groups is reported by Validate.
        var broadAccess = new Dictionary<string, string>();
        foreach (var (key, text) in groups.SelectMany(g => g.Reasons)) broadAccess.TryAdd(key, text);
        var policy = new Policy {
            Version = Text(root.GetProperty("version")),
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Tiers = root.GetProperty("tiers").EnumerateObject()
                .ToDictionary(t => t.Name, t => new TierText(Text(t.Value.GetProperty("name")), Text(t.Value.GetProperty("summary")))),
            Rules = rules,
            Groups = groups,
            BroadAccess = broadAccess,
            Combinations = [.. root.GetProperty("broadAccessCombinations").EnumerateArray()
                .Select(c => new Combination(Text(c.GetProperty("id")), Text(c.GetProperty("group")), Text(c.GetProperty("text")), [.. c.GetProperty("caps").EnumerateArray().Select(Text)]))],
            Labels = [.. root.GetProperty("labels").EnumerateArray().Select(l => new Label(Text(l.GetProperty("id")), Text(l.GetProperty("text")), Set(l.GetProperty("caps"))))],
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
            GameFolder = new Regex(Text(fa.GetProperty("gameFolder"))),
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
                Text(x.GetProperty("reason")),
                x.TryGetProperty("atCall", out var atCall) && atCall.GetBoolean())))];

    /// <summary>
    /// Whether a capability or finding raises the tier on its own, to Broad access (any group).
    /// What a game or library member passes on through overrides and patches is decided by this.
    /// </summary>
    public bool RaisesTier(string cap) => BroadAccess.ContainsKey(cap);

    /// <summary>The Broad-access group of a capability or finding, or null for none.</summary>
    public Group? GroupOf(string cap) => Groups.FirstOrDefault(g => g.Reasons.ContainsKey(cap));

    /// <summary>Every capability the analyzer can produce.</summary>
    public IEnumerable<string> ProducibleCaps => Rules.Where(r => r.Cap != Safe).Select(r => r.Cap)
        .Concat(Derived).Distinct();

    void Validate() {
        var errors = new List<string>();
        var labelled = Labels.SelectMany(l => l.Caps).ToHashSet();
        int Groups(string key) => this.Groups.Count(g => g.Reasons.ContainsKey(key));
        foreach (var cap in ProducibleCaps) {
            int homes = Groups(cap) + (labelled.Contains(cap) ? 1 : 0)
                + (FileKinds.ContainsKey(cap) ? 1 : 0) + (Informational.Contains(cap) ? 1 : 0);
            if (homes != 1) errors.Add($"capability '{cap}' must appear in exactly one of broadAccess (one group), labels, fileAccess.kinds, informational (found {homes})");
        }
        var producible = ProducibleCaps.ToHashSet();
        foreach (var g in this.Groups) {
            if (string.IsNullOrWhiteSpace(g.Name) || string.IsNullOrWhiteSpace(g.Summary)) errors.Add($"broadAccess group '{g.Id}' needs a name and a summary");
            if (g.Reasons.Count == 0) errors.Add($"broadAccess group '{g.Id}' has no reasons");
            foreach (var (key, text) in g.Reasons) {
                if (!producible.Contains(key) && !Findings.Contains(key)) errors.Add($"broadAccess.{g.Id} entry '{key}' is neither a capability nor a finding");
                if (string.IsNullOrWhiteSpace(text)) errors.Add($"broadAccess.{g.Id} entry '{key}' has no text");
            }
        }
        foreach (var f in Findings) {
            int homes = Groups(f);
            if (homes != 1) errors.Add($"finding '{f}' must appear in exactly one broadAccess group (found {homes})");
        }
        foreach (var name in this.Groups.GroupBy(g => g.Name, StringComparer.Ordinal).Where(g => g.Count() > 1))
            errors.Add($"the broadAccess group name '{name.Key}' is used more than once");
        // Each reason is shown to the user on its own: two that read the same cannot be told apart.
        foreach (var text in this.Groups.SelectMany(g => g.Reasons.Values).GroupBy(t => t, StringComparer.Ordinal).Where(g => g.Count() > 1))
            errors.Add($"the reason text '{text.Key}' is used more than once in broadAccess");
        // Results are keyed by label id: an id names one label, and reads as one (lowercase words and dashes).
        foreach (var l in Labels) {
            if (!Regex.IsMatch(l.Id, "^[a-z][a-z0-9]*(-[a-z0-9]+)*$")) errors.Add($"label id '{l.Id}' must be lowercase words joined by dashes");
            if (string.IsNullOrWhiteSpace(l.Text)) errors.Add($"label '{l.Id}' has no text");
        }
        foreach (var id in Labels.GroupBy(l => l.Id, StringComparer.Ordinal).Where(g => g.Count() > 1)) errors.Add($"the label id '{id.Key}' is used more than once");
        foreach (var text in Labels.GroupBy(l => l.Text, StringComparer.Ordinal).Where(g => g.Count() > 1)) errors.Add($"the label text '{text.Key}' is used more than once");
        foreach (var cap in labelled.Concat(Informational).Concat(FileKinds.Keys))
            if (!producible.Contains(cap)) errors.Add($"'{cap}' is referenced but no rule produces it");
        foreach (var c in Combinations) {
            if (RaisesTier(c.Id) || Combinations.Count(x => x.Id == c.Id) > 1) errors.Add($"broadAccessCombinations id '{c.Id}' is not unique");
            if (string.IsNullOrWhiteSpace(c.Text) || BroadAccess.Values.Contains(c.Text) || Combinations.Count(x => x.Text == c.Text) > 1)
                errors.Add($"broadAccessCombinations '{c.Id}' needs a text of its own");
            if (!this.Groups.Any(g => g.Id == c.Group)) errors.Add($"broadAccessCombinations '{c.Id}' names group '{c.Group}', which is not a broadAccess group");
            if (c.Caps.Count < 2 || c.Caps.Distinct().Count() != c.Caps.Count) errors.Add($"broadAccessCombinations '{c.Id}' needs at least two different capabilities");
            foreach (var cap in c.Caps) {
                if (!producible.Contains(cap)) errors.Add($"broadAccessCombinations '{c.Id}' references '{cap}', which no rule produces");
                // A Broad-access capability decides the tier on its own; a combination is made of
                // capabilities that are Limited access one by one.
                else if (GroupOf(cap) is { } g) errors.Add($"broadAccessCombinations '{c.Id}' references '{cap}', which is Broad access on its own ({g.Name})");
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
                if (!RaisesTier(cap) && !labelled.Contains(cap)) errors.Add($"{what} lists '{cap}', which is not a Broad-access capability, finding or label capability");
            if (x.Library == null && x.Caps.Any(Findings.Contains)) errors.Add($"{what} lists a finding; game profiles carry capabilities only");
            if (x.As != null && !labelled.Contains(x.As) && !(x.Library == null && RaisesTier(x.As) && !Findings.Contains(x.As)))
                errors.Add($"{what} passes on '{x.As}' instead, which is not a label capability (or, for the game, a Broad-access capability)");
            if (x.AtCall && x.Library == null) errors.Add($"{what} is marked atCall, which only a trusted-library exemption can be");
            if (string.IsNullOrWhiteSpace(x.Reason)) errors.Add($"{what} gives no reason");
        }
        foreach (var t in Enum.GetValues<Tier>())
            if (!Tiers.TryGetValue(t.Id(), out var tt)) errors.Add($"tiers has no name for '{t.Id()}'");
            else if (string.IsNullOrWhiteSpace(tt.Name) || string.IsNullOrWhiteSpace(tt.Summary)) errors.Add($"tier '{t.Id()}' needs a name and a summary");
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

    /// <summary>
    /// Whether a trusted-library member's exemption is accounted for at the mod's direct call ("atCall"):
    /// reached any other way, the arguments it checks at that call are not checked.
    /// </summary>
    /// <param name="library">Allowlist (assembly) name of the library.</param>
    /// <param name="member">"Namespace.Type::Member".</param>
    public bool CheckedAtCall(string library, string member) =>
        LibraryExempt.Any(x => x.AtCall && string.Equals(x.Library, library, StringComparison.OrdinalIgnoreCase) && x.Pattern.Matches(member, null));

    /// <summary>Whether some member of <paramref name="type"/> (or of a type nested in it) is <see cref="CheckedAtCall"/>.</summary>
    public bool CheckedAtCallInType(string library, string type) =>
        LibraryExempt.Any(x => x.AtCall && string.Equals(x.Library, library, StringComparison.OrdinalIgnoreCase)
            && (x.Pattern.Matches(type + "::", null) || x.Pattern.Text.StartsWith(type + "::", StringComparison.Ordinal) || x.Pattern.Text.StartsWith(type + "/", StringComparison.Ordinal)));

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
