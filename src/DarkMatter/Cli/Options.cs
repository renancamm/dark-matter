// SPDX-License-Identifier: MIT
namespace DarkMatter.Cli;

/// <summary>A command-line mistake; reported to the user with exit code 2.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>Minimal option parser: "--name value" options, bare flags and positional arguments.</summary>
internal sealed class Options {
    readonly Dictionary<string, List<string>> values = [];
    readonly HashSet<string> flags = [];

    public List<string> Positional { get; } = [];

    /// <summary>The option's value (the last one when it is given more than once), or null.</summary>
    public string? Get(string name) => values.TryGetValue(name, out var given) ? given[^1] : null;

    /// <summary>Every value of an option that can be given more than once, in the order given.</summary>
    public IReadOnlyList<string> GetAll(string name) => values.TryGetValue(name, out var given) ? given : [];

    public bool Has(params string[] names) => names.Any(flags.Contains);

    public static Options Parse(IReadOnlyList<string> argv, IReadOnlyCollection<string> valued, IReadOnlyCollection<string> flags) {
        var o = new Options();
        for (int i = 0; i < argv.Count; i++) {
            var a = argv[i];
            if (valued.Contains(a)) {
                if (i + 1 >= argv.Count) throw new UsageException($"{a} needs a value");
                if (!o.values.TryGetValue(a, out var given)) o.values[a] = given = [];
                given.Add(argv[++i]);
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
