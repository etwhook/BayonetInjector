#include "../../include/injector/injector.h";

using namespace injector;


HANDLE process::openProcess(DWORD processId) {
	HANDLE hProc;

	OBJECT_ATTRIBUTES objAtt { 0 };
	CLIENT_ID cid { 0 };

	cid.UniqueProcess = (HANDLE)processId;
	cid.UniqueThread = 0;

	NtOpenProcess(
		&hProc,
		PROCESS_SET_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | PROCESS_CREATE_THREAD,
		&objAtt,
		&cid
	);

	return hProc;
}
HANDLE process::openThread(DWORD threadId) {
	HANDLE hThr;

	OBJECT_ATTRIBUTES objAtt { 0 };
	CLIENT_ID cid { 0 };

	cid.UniqueProcess = 0;
	cid.UniqueThread = (HANDLE)threadId;
	
	NtOpenThread(
		&hThr,
		THREAD_ALL_ACCESS,
		&objAtt,
		&cid
	);

	return hThr;
}


PSYSTEM_PROCESS_INFORMATION process::getProcessInformation(const wchar_t* processName) {
	ULONG infoSize = 0;

	NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);
	LPVOID pProcessInfo = memory::heapAlloc(infoSize);

	NTSTATUS ok = NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, infoSize, &infoSize);

	auto processInfo = (PSYSTEM_PROCESS_INFORMATION)pProcessInfo;

	while (processInfo->NextEntryOffset != NULL) {

		if (!processInfo->ImageName.Buffer || !processInfo->ImageName.Length) {
			processInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)processInfo + processInfo->NextEntryOffset);
			continue;
		}

		if (wcscmp(processInfo->ImageName.Buffer, processName) == 0) {
			memory::heapFree(pProcessInfo); 
			return processInfo;
		}

		processInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)processInfo + processInfo->NextEntryOffset);
	}

	memory::heapFree(pProcessInfo); 
	return NULL; 
}

HANDLE process::createThread(HANDLE process, PVOID startAddr) {
	HANDLE hThread = NULL;

	NTSTATUS status = NtCreateThreadEx(
		&hThread,
		0x1FFFFF,
		NULL,
		process,
		startAddr,
		FALSE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);
	return hThread;
}

HANDLE process::createThreadArg(HANDLE process, PVOID startAddr, PVOID arg) {
	HANDLE hThread = NULL;

	NTSTATUS status = NtCreateThreadEx(
		&hThread,
		0x1FFFFF,
		NULL,
		process,
		startAddr,
		arg,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);
	return hThread;

}
bool process::simpleQueueAPC(HANDLE thread, PVOID startAddr) {

	return NT_SUCCESS(NtQueueApcThread(thread, (PKNORMAL_ROUTINE)startAddr, NULL, NULL, NULL));
}

vector<HANDLE> process::getThreads(PSYSTEM_PROCESS_INFORMATION procInfo) {
	vector<HANDLE> vThreads;
	auto threadsInfo = procInfo->Threads;

	for (size_t i = 0; i < procInfo->NumberOfThreads; i++)
	{
		auto tInfo = threadsInfo[i];
		vThreads.push_back(
			process::openThread(
				(DWORD)tInfo.ClientId.UniqueThread
			)
		);

	}
	return vThreads;
}

bool process::hijackExcThread(HANDLE thread, PVOID ripAddr) {
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_FULL;

	NtSuspendThread(thread, NULL);

	NtGetContextThread(thread, &threadContext);
	
	threadContext.Rip = (DWORD_PTR)ripAddr;

	NtSetContextThread(thread, &threadContext);
	return NT_SUCCESS(NtResumeThread(thread, NULL));
}

vector<MEMORY_BASIC_INFORMATION> process::getProcessMemoryRegions(HANDLE process) {
	vector<MEMORY_BASIC_INFORMATION> regions;
	MEMORY_BASIC_INFORMATION mbi { 0 };
	PVOID memAddr = NULL;

	while (NT_SUCCESS(NtQueryVirtualMemory(process, memAddr, MemoryBasicInformation, (PVOID)&mbi, sizeof(mbi), NULL))) {
		
		if (mbi.BaseAddress && mbi.State == MEM_COMMIT) {
			regions.push_back(mbi);
		}

		memAddr = reinterpret_cast<PVOID>((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
	}
	return regions;
}

PPROCESS_HANDLE_SNAPSHOT_INFORMATION process::getProcessHandleTable(HANDLE targetProcess) {
	ULONG handleInfoLen = 2 * 4 * 1024 * 4;
	PVOID pHandleInfo = memory::heapAlloc(handleInfoLen);

	NtQueryInformationProcess(targetProcess, (PROCESSINFOCLASS)ProcessHandleInformation, pHandleInfo, handleInfoLen, &handleInfoLen);

	return reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(pHandleInfo);
}

HANDLE process::hijackHandleFromTable(const wchar_t* objectName, PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleTable) {

	for (size_t i = 0; i < handleTable->NumberOfHandles; i++)
	{
		auto handleObject = handleTable->Handles[i];
		
		// soon
	}

}