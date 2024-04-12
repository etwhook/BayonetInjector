
# ⚔ Bayonet Injector

A Collection Of Native Implementations Of Injection Techniques Aimed To Assist With Game Hacking. 


## 👁 Techniques

#### Standard Injection
```cpp
auto shellcodeMemory = injector::memory::memAlloc(proc, PAGE_EXECUTE_READWRITE, sizeof sc);
 
injector::memory::memWrite(proc, shellcodeMemory, sc, sizeof sc);

injector::process::createThread(proc, shellcodeMemory);

```
#### Mapping Injection
```cpp
HANDLE section = injector::memory::secCreate(SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, sizeof sc, PAGE_EXECUTE_READWRITE);

PVOID localMap = injector::memory::secMap(section, injector::currentProcess, PAGE_READWRITE);

injector::memory::memWrite(injector::currentProcess, localMap, sc, sizeof sc);

PVOID procMap = injector::memory::secMap(section, proc, PAGE_EXECUTE_READ);

injector::process::createThread(proc, procMap);
```
#### APC Injection

```cpp
auto shellcodeMemory = injector::memory::memAlloc(proc, PAGE_EXECUTE_READWRITE, sizeof sc);

injector::memory::memWrite(proc, shellcodeMemory, sc, sizeof sc);

auto threads = injector::process::getThreads(processInfo);

for (auto& thr : threads) {
    if (injector::process::simpleQueueAPC(thr, shellcodeMemory)) {
        break;
    }
} 
```
#### Thread Hijacking
```cpp
auto procInfo = process::getProcessInformation(L"ProcessHacker.exe");
auto threads = process::getThreads(procInfo);
auto proc = process::openProcess((DWORD)procInfo->UniqueProcessId);

auto shellcodeMemory = injector::memory::memAlloc(proc, PAGE_EXECUTE_READWRITE, sizeof sc);
injector::memory::memWrite(proc, shellcodeMemory, sc, sizeof sc);

injector::process::hijackExcThread(threads[0], shellcodeMemory);
```

#### Instrumention Callback Injection

```cpp
// assuming you have valid shellcode allocated in the remote process that wouldnt recurse when the callback is executed.

injector::evasion::setProcessIC(process, shellcodeMemory);

```

## 🌟 Other Utils

#### Memory Enumeration

```cpp
auto regions = injector::process::getProcessMemoryRegions(proc);

for (auto& region : regions) {
    // region is of type MEMORY_BASIC_INFORMATION
    printf("Address ~> 0x%p\n", region.BaseAddress);
    printf("Size ~> %ld\n", region.RegionSize);
    printf("Allocation Protection ~> %ld\n", region.AllocationProtect);
}
```

#### SMBIOS Fetching
```cpp
auto SMBIOS = injector::utils::getSMBIOSHeaders();
```
## ❓ What's Next
Bayonet is still at a very early stage of development, And many changes to the library will occur and i will develop more advanced injection techniques aimed at bypassing usermode anti cheats, Like **Handle Hijacking** and **Pool Party**.

For the utilities part, i will develop **Pattern / Signature Scanning** (IDA) and **Value Scanning**.
## 🛡 Development
You're free to open a pull request or issue a bug fix.
