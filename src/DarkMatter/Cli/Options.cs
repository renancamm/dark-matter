// SPDX-License-Identifier: MIT
namespace DarkMatter.Cli;

/// <summary>A command-line mistake; reported to the user with exit code 2.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>Minimal option parser: "--name value" options, bare flags and positional arguments.</summary>
internal sealed class Options {
    readonly Dictionary<string, string> values = [];
    readonly HashSet<string> flags = [];

    public List<string> Positional { get; } = [];

    public string? Get(string name) => values.GetValueOrDefault(name);

    public bool Has(params string[] names) => names.Any(flags.Contains);

    public static Options Parse(IReadOnlyList<string> argv, IReadOnlyCollection<string> valued, IReadOnlyCollection<string> flags) {
        var o = new Options();
        for (int i = 0; i < argv.Count; i++) {
            var a = argv[i];
            if (valued.Contains(a)) {
                if (i + 1 >= argv.Count) throw new UsageException($"{a} needs a value");
                o.values[a] = argv[++i];
            } else if (flags.Contains(a)) {
                o.flags.Add(a);
            } else if (a.StartsWith('-') && a.Length > 1) {
                throw new UsageException($"unknown option {a}");
            } else {
                o.Positional.Add(a);
            }
        }
        return o;
    }
}
