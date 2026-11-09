// SPDX-License-Identifier: MIT
// A mod whose type and member names are markup and a bidirectional override, for the HTML report
// (scripts/test_fixtures.py, group "scan"). C# cannot spell such names, but .NET metadata can:
// the harness replaces each placeholder name below in the built assembly with a markup name of
// the same length in bytes. Both methods connect to the internet, so their names (and the type's)
// appear in the label's evidence, which the report must show as text.
using System.Net.Http;

namespace Markup;

public class MarkupTypeNameXXXXXXXXXXX {
    public void MarkupMethodNameXXXXXXXXXXXXXX() => new HttpClient().GetAsync("https://example.invalid/");

    public void MarkupBidiXXXX() => new HttpClient().GetAsync("https://example.invalid/");
}
