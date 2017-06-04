# CoWDump

CopyOnWriteDump is a tool that uses the [Process Snapshotting](https://msdn.microsoft.com/en-us/library/dn469412(v=vs.85).aspx) APIs available in Windows 8.1+ and Windows Server 2012 R2+ to capture full memory dumps of Win32 user-mode processes.

Process Snapshotting APIs use [Copy-on-Write](https://en.wikipedia.org/wiki/Copy-on-write) semantics to capture a "snapshot" of the target process. The target process is suspended for the duration of snapshot creation (its latency is usually orders of magnitude lower than capturing a full memory dump) and is then resumed.

## Download

* 64-bit Processes:  [CopyOnWriteDump.exe](https://github.com/mjsabby/CoWDump/raw/master/CopyOnWriteDump.exe)
* 32-bit Processes (even when using on 64-bit Windows):  [CopyOnWriteDump32.exe](https://github.com/mjsabby/CoWDump/raw/master/CopyOnWriteDump32.exe)
