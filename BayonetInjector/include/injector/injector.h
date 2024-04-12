#pragma once
#include<vector>
#include<optional>
#include<memory>
#include "../syscalls/syscalls.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

using std::vector;
using std::optional;

namespace injector {
	
	static HANDLE currentProcess = GetCurrentProcess();
	// main injection class //
	class Bayonet {

	public:
		HANDLE targetProcess;
		HANDLE currentProcess = injector::currentProcess;

	};

	namespace process {
		HANDLE openProcess(DWORD processId);
		HANDLE openThread(DWORD threadId);

		PSYSTEM_PROCESS_INFORMATION getProcessInformation(const wchar_t* processName);

		PPROCESS_HANDLE_SNAPSHOT_INFORMATION getProcessHandleTable(HANDLE targetProcess);
		HANDLE hijackHandleFromTable(const wchar_t* objectName, PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleTable);

		vector<MEMORY_BASIC_INFORMATION> getProcessMemoryRegions(HANDLE process);

		vector<HANDLE> getThreads(PSYSTEM_PROCESS_INFORMATION procInfo);
		
		HANDLE createThread(HANDLE process, PVOID startAddr);
		HANDLE createThreadArg(HANDLE process, PVOID startAddr, PVOID arg);
		bool simpleQueueAPC(HANDLE thread, PVOID startAddr);

		bool hijackExcThread(HANDLE thread, PVOID ripAddr);

	}
	
	namespace memory {
		static HANDLE heap = GetProcessHeap();

		PVOID heapAlloc(SIZE_T memSize);
		void heapFree(PVOID memAddr);

		PVOID memAlloc(HANDLE process, ACCESS_MASK protection, SIZE_T bufferSize);
		bool memWrite(HANDLE process, PVOID memAddress, PVOID buffer, SIZE_T writeAmount);

		HANDLE secCreate(ACCESS_MASK access, SIZE_T secSize, ULONG protection);
		PVOID secMap(HANDLE sectionHandle, HANDLE process, ULONG protect);
	}

	namespace evasion {
	
		bool setCurrentProcessIC(PVOID callBack);
		bool setProcessIC(HANDLE process, PVOID callBack);
	}
	
}