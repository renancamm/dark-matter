// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace DarkMatter.Pipeline.Index;

/// <summary>A document that is not valid TOML (or uses a form this reader does not accept).</summary>
internal sealed class TomlException(string message) : Exception(message);

/// <summary>A TOML table: key -> string, <see cref="TomlTable"/>, <see cref="TomlArray"/> or <see cref="TomlScalar"/>.</summary>
internal sealed class TomlTable {
    public Dictionary<string, object> Items { get; } = new(StringComparer.Ordinal);

    internal TableState State { get; set; }
}

internal enum TableState { Implicit, Header, Dotted, Inline }

/// <summary>A TOML array; <paramref name="OfTables"/> for one built by [[header]] tables.</summary>
internal sealed record TomlArray(List<object> Items, bool OfTables);

/// <summary>A number, boolean or date, kept as written: the pipeline reads only strings.</summary>
internal sealed record TomlScalar(string Raw);

/// <summary>
/// A minimal TOML reader for content-index listings (no package dependency). It reads the whole
/// structure (strings, arrays, inline tables, table and array-of-table headers, dotted and quoted
/// keys) so that it always knows which table a key is in: a "[releases]" line inside a
/// multi-line description string is text, not a table. Strings are decoded; numbers, booleans and
/// dates are only checked for their form and kept as written. Duplicate keys, tables defined twice
/// and anything malformed are errors, never skipped.
/// </summary>
internal static partial class Toml {
    public static TomlTable Parse(string text) => new Parser(text).Document();

    // Bare values: booleans, integers (decimal, hex, octal, binary), floats, dates and times.
    [GeneratedRegex(@"^(true|false|[+-]?(0|[1-9](_?[0-9])*)|0x[0-9A-Fa-f](_?[0-9A-Fa-f])*|0o[0-7](_?[0-7])*|0b[01](_?[01])*"
        + @"|[+-]?(0|[1-9](_?[0-9])*)((\.[0-9](_?[0-9])*)([eE][+-]?[0-9](_?[0-9])*)?|[eE][+-]?[0-9](_?[0-9])*)|[+-]?(inf|nan)"
        + @"|[0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?([Zz]|[+-][0-9]{2}:[0-9]{2})?)?"
        + @"|[0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?)$")]
    private static partial Regex BareValue();

    sealed class Parser(string s) {
        int i;

        TomlException Error(string message) => new($"line {s.AsSpan(0, Math.Min(i, s.Length)).Count('\n') + 1}: {message}");

        char Peek(int k = 0) => i + k < s.Length ? s[i + k] : '\0';
        bool End => i >= s.Length;
        bool AtNewline => Peek() == '\n' || (Peek() == '\r' && Peek(1) == '\n');

        public TomlTable Document() {
            var root = new TomlTable { State = TableState.Header };
            var current = root;
            while (true) {
                SkipSpaces();
                if (End) return root;
                if (Peek() == '[') current = Header(root);
                else if (Peek() != '#' && !AtNewline) KeyValue(current);
                EndOfLine();
            }
        }

        void SkipSpaces() {
            while (Peek() is ' ' or '\t') i++;
        }

        void SkipComment() {
            if (Peek() != '#') return;
            for (; !End && !AtNewline; i++)
                if (char.IsControl(s[i]) && s[i] != '\t') throw Error("control character in a comment");
        }

        bool Newline() {
            if (Peek() == '\n') i++;
            else if (Peek() == '\r' && Peek(1) == '\n') i += 2;
            else return false;
            return true;
        }

        void EndOfLine() {
            SkipSpaces();
            SkipComment();
            if (!End && !Newline()) throw Error($"unexpected {Describe(Peek())}");
        }

        /// <summary>Spaces, newlines and comments, as allowed between array elements.</summary>
        void SkipBlank(bool newlines) {
            while (true) {
                SkipSpaces();
                SkipComment();
                if (!newlines || !Newline()) return;
            }
        }

        static string Describe(char c) => char.IsControl(c) ? $"character U+{(int)c:X4}" : $"'{c}'";

        void Expect(char c) {
            if (Peek() != c) throw Error(End ? $"expected '{c}', found the end of the file" : $"expected '{c}', found {Describe(Peek())}");
            i++;
        }

        TomlTable Header(TomlTable root) {
            bool array = Peek(1) == '[';
            i += array ? 2 : 1;
            SkipSpaces();
            var key = Key();
            SkipSpaces();
            Expect(']');
            if (array) Expect(']');
            var t = root;
            foreach (var part in key[..^1]) t = Descend(t, part, header: true);
            var last = key[^1];
            var name = string.Join('.', key);
            if (array) {
                TomlArray tables;
                if (!t.Items.TryGetValue(last, out var v)) t.Items[last] = tables = new TomlArray([], OfTables: true);
                else if (v is TomlArray { OfTables: true } a) tables = a;
                else throw Error($"[[{name}]]: {name} is already defined");
                var table = new TomlTable { State = TableState.Header };
                tables.Items.Add(table);
                return table;
            }
            if (!t.Items.TryGetValue(last, out var existing)) {
                var table = new TomlTable { State = TableState.Header };
                t.Items[last] = table;
                return table;
            }
            if (existing is TomlTable { State: TableState.Implicit } it) {
                it.State = TableState.Header;
                return it;
            }
            throw Error($"[{name}]: {name} is already defined");
        }

        /// <summary>The table <paramref name="key"/> of <paramref name="t"/>, created if missing.</summary>
        TomlTable Descend(TomlTable t, string key, bool header) {
            if (!t.Items.TryGetValue(key, out var v)) {
                var table = new TomlTable { State = header ? TableState.Implicit : TableState.Dotted };
                t.Items[key] = table;
                return table;
            }
            switch (v) {
                case TomlTable { State: TableState.Inline }:
                    throw Error($"{key} is an inline table and cannot be extended");
                case TomlTable table when header:
                    return table;
                case TomlTable { State: TableState.Header }:
                    throw Error($"a dotted key cannot add to table {key}, which a header defines");
                case TomlTable table:
                    table.State = TableState.Dotted;
                    return table;
                case TomlArray { OfTables: true } tables when header:
                    return (TomlTable)tables.Items[^1];
                default:
                    throw Error($"{key} is already defined as a value");
            }
        }

        void KeyValue(TomlTable current) {
            var key = Key();
            SkipSpaces();
            Expect('=');
            SkipSpaces();
            var value = Value();
            var t = current;
            foreach (var part in key[..^1]) t = Descend(t, part, header: false);
            if (!t.Items.TryAdd(key[^1], value)) throw Error($"{string.Join('.', key)} is defined twice");
        }

        List<string> Key() {
            var parts = new List<string>();
            while (true) {
                parts.Add(Peek() switch {
                    '"' => BasicString(),
                    '\'' => LiteralString(),
                    _ => BareKey(),
                });
                SkipSpaces();
                if (Peek() != '.') return parts;
                i++;
                SkipSpaces();
            }
        }

        string BareKey() {
            int start = i;
            while (Peek() is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-') i++;
            if (i == start) throw Error(End ? "expected a key, found the end of the file" : $"expected a key, found {Describe(Peek())}");
            return s[start..i];
        }

        object Value() {
            if (Peek() == '"') return Peek(1) == '"' && Peek(2) == '"' ? MultiLineBasicString() : BasicString();
            if (Peek() == '\'') return Peek(1) == '\'' && Peek(2) == '\'' ? MultiLineLiteralString() : LiteralString();
            if (Peek() == '[') return Array();
            if (Peek() == '{') return InlineTable();
            return Bare();
        }

        TomlScalar Bare() {
            int start = i;
            while (!End && Peek() is not (' ' or '\t' or '\r' or '\n' or ',' or ']' or '}' or '#')) i++;
            // A date and time may be separated by a space.
            if (IsDate(s.AsSpan(start, i - start)) && Peek() == ' ' && char.IsAsciiDigit(Peek(1)) && char.IsAsciiDigit(Peek(2)) && Peek(3) == ':') {
                i++;
                while (!End && Peek() is not (' ' or '\t' or '\r' or '\n' or ',' or ']' or '}' or '#')) i++;
            }
            var raw = s[start..i];
            if (raw.Length == 0) throw Error(End ? "expected a value, found the end of the file" : $"expected a value, found {Describe(Peek())}");
            if (!BareValue().IsMatch(raw)) throw Error($"not a valid value: {Text.Quote(raw)}");
            return new TomlScalar(raw);
        }

        static bool IsDate(ReadOnlySpan<char> v) =>
            v.Length == 10 && v[4] == '-' && v[7] == '-' && char.IsAsciiDigit(v[0]) && char.IsAsciiDigit(v[1]) && char.IsAsciiDigit(v[2])
            && char.IsAsciiDigit(v[3]) && char.IsAsciiDigit(v[5]) && char.IsAsciiDigit(v[6]) && char.IsAsciiDigit(v[8]) && char.IsAsciiDigit(v[9]);

        TomlArray Array() {
            Expect('[');
            var items = new List<object>();
            while (true) {
                SkipBlank(newlines: true);
                if (Peek() == ']') break;
                items.Add(Value());
                SkipBlank(newlines: true);
                if (Peek() == ',') {
                    i++;
                    continue;
                }
                if (Peek() != ']') throw Error(End ? "unterminated array" : $"expected ',' or ']' in an array, found {Describe(Peek())}");
            }
            i++;
            return new TomlArray(items, OfTables: false);
        }

        // TOML 1.1 allows newlines and a trailing comma inside inline tables; accepted here too.
        TomlTable InlineTable() {
            Expect('{');
            var table = new TomlTable { State = TableState.Dotted };
            while (true) {
                SkipBlank(newlines: true);
                if (Peek() == '}') break;
                KeyValue(table);
                SkipBlank(newlines: true);
                if (Peek() == ',') {
                    i++;
                    continue;
                }
                if (Peek() != '}') throw Error(End ? "unterminated inline table" : $"expected ',' or '}}' in an inline table, found {Describe(Peek())}");
            }
            i++;
            Freeze(table);
            return table;
        }

        static void Freeze(TomlTable t) {
            t.State = TableState.Inline;
            foreach (var v in t.Items.Values)
                if (v is TomlTable { State: TableState.Dotted } inner) Freeze(inner);
        }

        void CheckChar(char c, bool multiLine) {
            if (c == '\t' || (multiLine && c is '\n' or '\r')) return;
            if (char.IsControl(c)) throw Error($"control character U+{(int)c:X4} in a string");
        }

        string BasicString() {
            Expect('"');
            var b = new StringBuilder();
            while (true) {
                if (End || AtNewline || Peek() == '\n') throw Error("unterminated string");
                char c = s[i++];
                if (c == '"') return b.ToString();
                if (c == '\\') Escape(b);
                else {
                    CheckChar(c, multiLine: false);
                    b.Append(c);
                }
            }
        }

        string MultiLineBasicString() {
            i += 3;
            Newline();  // a newline right after the opening quotes is not part of the string
            var b = new StringBuilder();
            while (true) {
                if (End) throw Error("unterminated multi-line string");
                if (Closing('"', b)) return b.ToString();
                char c = s[i++];
                if (c == '\\') {
                    // A backslash at the end of a line removes the newline and the blank space after it.
                    int save = i;
                    SkipSpaces();
                    if (AtNewline) {
                        while (Peek() is ' ' or '\t' || AtNewline) {
                            if (!Newline()) i++;
                        }
                        continue;
                    }
                    i = save;
                    Escape(b);
                } else {
                    if (c == '\r' && Peek() != '\n') throw Error("bare carriage return in a string");
                    CheckChar(c, multiLine: true);
                    b.Append(c);
                }
            }
        }

        string LiteralString() {
            Expect('\'');
            int start = i;
            while (true) {
                if (End || AtNewline || Peek() == '\n') throw Error("unterminated string");
                char c = s[i++];
                if (c == '\'') return s[start..(i - 1)];
                CheckChar(c, multiLine: false);
            }
        }

        string MultiLineLiteralString() {
            i += 3;
            Newline();
            var b = new StringBuilder();
            while (true) {
                if (End) throw Error("unterminated multi-line string");
                if (Closing('\'', b)) return b.ToString();
                char c = s[i++];
                if (c == '\r' && Peek() != '\n') throw Error("bare carriage return in a string");
                CheckChar(c, multiLine: true);
                b.Append(c);
            }
        }

        /// <summary>
        /// At three or more quotes: the string ends, and up to two quotes before the closing three
        /// belong to it. Six or more in a row is an error.
        /// </summary>
        bool Closing(char quote, StringBuilder b) {
            int n = 0;
            while (Peek(n) == quote) n++;
            if (n < 3) return false;
            if (n > 5) throw Error("too many quotes at the end of a multi-line string");
            b.Append(quote, n - 3);
            i += n;
            return true;
        }

        void Escape(StringBuilder b) {
            if (End) throw Error("unterminated string");
            char c = s[i++];
            switch (c) {
                case 'b': b.Append('\b'); break;
                case 't': b.Append('\t'); break;
                case 'n': b.Append('\n'); break;
                case 'f': b.Append('\f'); break;
                case 'r': b.Append('\r'); break;
                case 'e': b.Append('\u001B'); break;  // TOML 1.1
                case '"': b.Append('"'); break;
                case '\\': b.Append('\\'); break;
                case 'x': b.Append(CodePoint(2)); break;  // TOML 1.1
                case 'u': b.Append(CodePoint(4)); break;
                case 'U': b.Append(CodePoint(8)); break;
                default: throw Error($"invalid escape '\\{Text.Printable(c.ToString())}'");
            }
        }

        string CodePoint(int digits) {
            if (i + digits > s.Length || !s.AsSpan(i, digits).ContainsOnlyHex()) throw Error($"expected {digits} hexadecimal digits in an escape");
            var v = int.Parse(s.AsSpan(i, digits), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            i += digits;
            if (v > 0x10FFFF || v is >= 0xD800 and <= 0xDFFF || v < 0) throw Error("escape is not a Unicode scalar value");
            return char.ConvertFromUtf32(v);
        }
    }
}

file static class SpanExtensions {
    public static bool ContainsOnlyHex(this ReadOnlySpan<char> s) {
        foreach (var c in s) if (!char.IsAsciiHexDigit(c)) return false;
        return true;
    }
}
