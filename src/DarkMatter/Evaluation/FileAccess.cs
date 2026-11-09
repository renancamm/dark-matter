// SPDX-License-Identifier: MIT
using DarkMatter.Analysis;

namespace DarkMatter.Evaluation;

/// <summary>
/// Decides where the path of each file operation comes from. The walker records the path atoms of
/// each operation's path operand (see <see cref="FileOp"/>): origins, and references to the
/// arguments of the method, fields and other methods' results. Those are resolved here across all
/// analyzed assemblies of a mod: an argument from every call that passes it, a field from every
/// store to it, a result from every value the method returns. A reference that cannot be followed
/// (no analyzed caller, a field other code can assign, a method that was not analyzed or can be
/// overridden) is untraced, and an operation whose path comes from nowhere the check can name
/// counts as outside the game. Assembly names in node keys are compared ignoring case.
/// </summary>
internal static class FileAccess {
    /// <param name="assemblies">The assemblies analyzed together.</param>
    /// <param name="policy">The policy whose file kinds and origins apply.</param>
    /// <param name="fieldsWritten">Whether a type's fields can be written through reflection, from
    /// <see cref="FieldProvenance.FieldsWritten"/> (writes through traced fields, parameters and
    /// return values included); null to use only the writes each method makes directly.</param>
    /// <param name="reflected">Whether a method (by node key) can be reached by reflection, from
    /// <see cref="FieldProvenance.ReachedByReflection"/>: it is then called with arguments the check does
    /// not see, as one called from outside is; null to count only the methods called from outside.</param>
    public static List<(MethodFacts Method, Evidence Evidence)> Classify(IReadOnlyCollection<AssemblyFacts> assemblies, Policy policy, Func<string, bool>? fieldsWritten = null,
        Func<string, bool>? reflected = null) {
        var methods = assemblies.SelectMany(a => a.Methods).ToList();
        var resolver = new Resolver(assemblies, methods, fieldsWritten, reflected);
        List<(MethodFacts, Evidence)> result = [];
        foreach (var m in methods) {
            foreach (var op in m.FileOps) {
                var origins = resolver.Origins(op.Path);
                // Where the path begins or ends is not traced (see PathAtoms.Head, End): not an origin.
                bool loose = origins.Remove(PathAtoms.Head) || m.DecodeFailed;
                origins.Remove(PathAtoms.End);
                if (m.DecodeFailed) origins.Add(PathAtoms.Untraced);
                if (origins.Count == 0) origins.Add(PathAtoms.Untraced);  // a relative literal alone: wherever the current folder is
                var outside = origins.Where(o => !policy.InsideOrigins.Contains(o)).ToList();
                // The mod's own folder and the game's folders are where the loader finds mod code
                // (any DLL in a mod folder, mod.toml, *.deps.json, the game's mod manifest).
                bool code = origins.Any(policy.CodeOrigins.Contains);
                string detail = $"{op.Member}  <-  {m.Name}  (path from: {string.Join(", ", origins.Order(StringComparer.Ordinal))})";
                bool writes = op.Kind == FileOpKind.Write;
                if (writes && origins.Contains("saves")) result.Add((m, new("file-saves", detail, Origin.Reference)));
                if (writes && code) result.Add((m, new("file-write-code", detail, Origin.Reference)));
                if (outside.Count > 0) result.Add((m, new(writes ? "file-write-outside" : "file-read-outside", detail, Origin.Reference)));
                // A web address in place of a path, or a path whose beginning the check cannot trace, which
                // could make it one. A path that begins with a folder the check traced (the mod's, the
                // game's, a user folder, a rooted literal) is a file, whatever is appended to it.
                if (op.Url && (origins.Contains(PathAtoms.Url) || loose)) result.Add((m, new("network", detail, Origin.Reference)));
            }
            // Opening a folder the method has just created: the file manager, when the folder is in the
            // mod's or the game's folders and its name has no extension (a macOS ".app" folder is a
            // program, a Windows folder named with a class id a shell extension); anything else counts as
            // starting a program.
            foreach (var open in m.FolderOpens) {
                var origins = resolver.Origins(open.Path);
                origins.Remove(PathAtoms.Head);
                bool named = !origins.Remove(PathAtoms.End);
                if (m.DecodeFailed || origins.Count == 0) origins.Add(PathAtoms.Untraced);
                bool inside = named && origins.All(policy.InsideOrigins.Contains);
                string detail = $"{open.Member}  <-  {m.Name}  (a folder it creates{(named ? "" : ", whose name may have an extension")}, path from: {string.Join(", ", origins.Order(StringComparer.Ordinal))})";
                result.Add((m, new(inside ? "shell-open-folder" : "process-start", detail, Origin.Reference)));
            }
        }
        return result;
    }

    // Resolves path atoms to origins: the least solution of the references' definitions.
    sealed class Resolver {
        readonly Dictionary<string, List<MethodFacts>> byKey = new(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, HashSet<string>> arguments = new(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, HashSet<string>> stores = new(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> own = new(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> open = new(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> written = new(StringComparer.Ordinal);  // types whose fields are written through reflection
        readonly Func<string, bool> fieldsWritten;
        readonly Func<string, bool> reflected;
        readonly Dictionary<string, HashSet<string>> value = new(StringComparer.OrdinalIgnoreCase);

        public Resolver(IReadOnlyCollection<AssemblyFacts> assemblies, List<MethodFacts> methods, Func<string, bool>? fieldsWritten, Func<string, bool>? reflected) {
            this.reflected = reflected ?? (_ => false);
            // Without the provenance's view, a write to "T+" (T or a derived type) counts for T only:
            // used for the game profile, whose own reflection the check does not hold against it.
            this.fieldsWritten = fieldsWritten ?? (type => written.Contains("*") || written.Contains(type) || written.Contains(type + "+"));
            foreach (var a in assemblies) { own.Add(a.Name); open.UnionWith(a.OpenPathFields); }
            foreach (var m in methods) {
                Add(byKey, m.Key, m);
                foreach (var (k, atoms) in m.PathArguments) Set(arguments, k).UnionWith(atoms);
                foreach (var (k, atoms) in m.PathStores) Set(stores, k).UnionWith(atoms);
                written.UnionWith(m.ReflectionFieldWrites);
            }
        }

        public HashSet<string> Origins(IEnumerable<string> atoms) {
            var refs = atoms.Where(IsReference).ToList();
            if (refs.Any(r => !value.ContainsKey(r))) Solve(refs);
            var origins = new HashSet<string>(StringComparer.Ordinal);
            foreach (var a in atoms) origins.UnionWith(IsReference(a) ? value[a] : [a]);
            // The Documents folder itself (see PathAtoms.DocumentsFolder) is in Documents, like anything in it.
            return [.. origins.Select(PathAtoms.Plain)];
        }

        static bool IsReference(string a) => PathAtoms.IsReference(a);

        // Every reference reachable from roots, then their values by iteration until nothing
        // changes (values only grow, and are sets of the finitely many origins).
        void Solve(IEnumerable<string> roots) {
            var todo = new Stack<string>(roots);
            var fresh = new List<string>();
            while (todo.Count > 0) {
                var a = todo.Pop();
                if (value.ContainsKey(a)) continue;
                value[a] = new(StringComparer.Ordinal);
                fresh.Add(a);
                foreach (var d in Definition(a).Where(IsReference)) todo.Push(d);
            }
            for (bool changed = true; changed;) {
                changed = false;
                foreach (var a in fresh) {
                    var next = Evaluate(a);
                    if (!next.IsSubsetOf(value[a])) { value[a].UnionWith(next); changed = true; }
                }
            }
        }

        HashSet<string> Evaluate(string atom) {
            var result = new HashSet<string>(StringComparer.Ordinal);
            // Appended to a path (or followed by more of it): its origins, not where it begins (ends); the
            // Documents folder itself is no longer the whole path, nor in something made from it.
            if (PathAtoms.Positioned(atom) is var (reference, drops)) {
                result.UnionWith(value[reference].Select(PathAtoms.Plain));
                result.Remove(drops);
                return result;
            }
            if (PathAtoms.Made(atom) is { } made) {
                result.UnionWith(value[made].Select(PathAtoms.Plain));
                return result;
            }
            if (PathAtoms.InGame(atom) is { } named) {
                // Followed directly by the game's folder names: the Documents folder itself is the game's folder.
                foreach (var o in value[named]) result.Add(o == PathAtoms.DocumentsFolder ? "game" : o);
                return result;
            }
            foreach (var d in Definition(atom)) result.UnionWith(IsReference(d) ? value[d] : [d]);
            return result;
        }

        // The atoms a reference stands for.
        IEnumerable<string> Definition(string atom) {
            if (PathAtoms.Positioned(atom) is var (reference, _)) return [reference];
            if (PathAtoms.Made(atom) is { } made) return [made];
            if (PathAtoms.InGame(atom) is { } named) return [named];
            if (atom.StartsWith("arg:", StringComparison.Ordinal)) {
                var k = atom[4..];
                var method = k[..k.LastIndexOf('#')];
                // A method that is not analyzed, is taken as a delegate, or can be reached by a
                // virtual call (an override, an interface method) gets arguments from calls the
                // check does not see; so does one no analyzed code calls.
                if (!byKey.TryGetValue(method, out var ms) || ms.Any(m => m.IsVirtual) || arguments.ContainsKey(method + "#*")
                    || !arguments.TryGetValue(k, out var passed))
                    return [PathAtoms.Untraced, PathAtoms.Head, PathAtoms.End];
                // One that code not analyzed with it can call (public, a Harmony patch method, attributed;
                // see MethodFacts.CalledFromOutside), or that reflection can reach (MethodBase.Invoke: H7 review;
                // before, a private helper found by name kept only its direct calls' paths), gets those
                // arguments as well as the ones seen here.
                if (ms.Any(m => m.CalledFromOutside != null) || reflected(method)) return [.. passed, PathAtoms.Untraced, PathAtoms.Head, PathAtoms.End];
                return passed;
            }
            if (atom.StartsWith("field:", StringComparison.Ordinal)) {
                var f = atom[6..];
                int bar = f.IndexOf('|', StringComparison.Ordinal), sep = f.IndexOf("::", StringComparison.Ordinal);
                if (bar < 0 || sep < bar || !own.Contains(f[..bar]) || open.Contains(f) || fieldsWritten(f[(bar + 1)..sep]))
                    return [PathAtoms.Untraced, PathAtoms.Head, PathAtoms.End];
                // A field that is never stored holds null (a path that begins or ends with it begins or ends with what is next to it).
                return stores.TryGetValue(f, out var stored) ? stored : [PathAtoms.Head, PathAtoms.End];
            }
            var key = atom[4..];  // ret:
            if (!byKey.TryGetValue(key, out var callees) || callees.Any(m => m.IsVirtual || m.DecodeFailed)) return [PathAtoms.Untraced, PathAtoms.Head, PathAtoms.End];
            return callees.SelectMany(m => m.PathReturns);
        }

        static void Add(Dictionary<string, List<MethodFacts>> d, string key, MethodFacts m) {
            if (!d.TryGetValue(key, out var list)) d[key] = list = [];
            list.Add(m);
        }

        static HashSet<string> Set(Dictionary<string, HashSet<string>> d, string key) {
            if (!d.TryGetValue(key, out var set)) d[key] = set = new(StringComparer.Ordinal);
            return set;
        }
    }
}
