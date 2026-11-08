// SPDX-License-Identifier: MIT
// Probe case: a file method taken as a delegate (ldftn) and called through it. The path is passed
// at the delegate call, which file-path tracing does not connect to File.Delete. Expected:
// "Changes files outside the game".
using System;
using System.IO;

public class MethodGroupDeleteCase {
    public static void Run(string path) {
        Action<string> delete = File.Delete;
        delete(path);
    }
}
