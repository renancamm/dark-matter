// SPDX-License-Identifier: MIT
// H9 (policy 29): TextFieldParser(path) opens a file, traced like the other file reads: one in the mod's
// own folder has no label (before H9: unclassified). CsvOutside reads one from Documents.
using System.IO;
using Microsoft.VisualBasic.FileIO;

public static class CsvOwnFolder {
    public static int Count() {
        var dir = Path.GetDirectoryName(typeof(CsvOwnFolder).Assembly.Location)!;
        using var parser = new TextFieldParser(Path.Combine(dir, "stars.csv"));
        parser.TextFieldType = FieldType.Delimited;
        parser.SetDelimiters(",");
        parser.HasFieldsEnclosedInQuotes = true;
        int n = 0;
        while (!parser.EndOfData) n += parser.ReadFields()?.Length ?? 0;
        return n + (int)parser.LineNumber;
    }
}
