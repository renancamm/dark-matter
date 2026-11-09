// SPDX-License-Identifier: MIT
// H9 control: ordinary C# delegates (ldftn of a lambda, of a framework method group, ldvirtftn of a virtual
// method group) are not native code: Limited access, nothing labelled.
using System;

public static class DelegatesOrdinary {
    public static int Run(object o, string s) {
        Func<string, int> parse = int.Parse;
        Func<string> text = o.ToString;
        Func<int, int> twice = x => x * 2;
        Action<string> print = Console.WriteLine;
        print(text());
        return twice(parse(s));
    }
}
