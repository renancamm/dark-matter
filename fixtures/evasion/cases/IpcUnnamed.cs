// SPDX-License-Identifier: MIT
// H9 (policy 29): unnamed Mutex, Semaphore and EventWaitHandle are the process's own: Limited access,
// nothing labelled (before H9: the Mutex and Semaphore members were unclassified).
using System.Threading;

public static class IpcUnnamed {
    public static void Run() {
        using var mutex = new Mutex();
        using var owned = new Mutex(true);
        owned.ReleaseMutex();
        using var semaphore = new Semaphore(0, 2);
        semaphore.Release();
        semaphore.WaitOne();
        using var ev = new EventWaitHandle(false, EventResetMode.ManualReset);
        ev.Set();
        mutex.WaitOne();
        mutex.ReleaseMutex();
    }
}
