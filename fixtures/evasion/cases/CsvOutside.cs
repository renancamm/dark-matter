// SPDX-License-Identifier: MIT
// H9 (policy 29): TextFieldParser(path) on a file outside the game is "Reads files outside the game".
using System;
using System.IO;
using Microsoft.VisualBasic.FileIO;

public static class CsvOutside {
    public static string[]? First() {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        using var parser = new TextFieldParser(Path.Combine(docs, "notes.csv"));
        parser.SetDelimiters(";");
        return parser.ReadFields();
    }
}
