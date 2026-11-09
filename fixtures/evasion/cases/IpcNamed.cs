// SPDX-License-Identifier: MIT
// H9 (policy 29): named kernel objects are shared with every program of the user: "Communicates with
// other programs on your computer" (ipc). Before H9: unclassified (Full access, not fully checked).
using System.Threading;

public static class IpcNamed {
    public static bool Signal() {
        using var mutex = new Mutex(false, "ExampleMod.Lock");
        bool owned = mutex.WaitOne(0);
        if (owned) mutex.ReleaseMutex();
        using var semaphore = new Semaphore(0, 1, "ExampleMod.Slots");
        bool open = EventWaitHandle.TryOpenExisting("ExampleMod.Ready", out var ready);
        ready?.Dispose();
        return owned && open;
    }
}
