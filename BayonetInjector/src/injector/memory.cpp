#include "../../include/injector/injector.h";

using namespace injector;

PVOID memory::heapAlloc(SIZE_T memSize) {
	return HeapAlloc(memory::heap, HEAP_ZERO_MEMORY, memSize);
}

void memory::heapFree(PVOID memAddr) {
	HeapFree(memory::heap, 0, memAddr);
}

PVOID memory::memAlloc(HANDLE process, ACCESS_MASK protection, SIZE_T bufferSize) {
	PVOID memAddr = NULL;
	NtAllocateVirtualMemory(process, &memAddr, 0, &bufferSize, MEM_COMMIT | MEM_RESERVE, protection);
	return memAddr;
}

bool memory::memWrite(HANDLE process, PVOID memAddress, PVOID buffer, SIZE_T writeAmount) {
	return NT_SUCCESS(NtWriteVirtualMemory(process, memAddress, buffer, writeAmount, NULL));
}

HANDLE memory::secCreate(ACCESS_MASK access, SIZE_T secSize, ULONG protection) {
	HANDLE sectionHandle = NULL;
	NtCreateSection(&sectionHandle, access, NULL, (PLARGE_INTEGER)&secSize, protection, SEC_COMMIT, NULL);
	return sectionHandle;
}

PVOID memory::secMap(HANDLE sectionHandle, HANDLE process, ULONG protect) {
	PVOID viewAddr = NULL;
	SIZE_T viewSize = 0;
	NtMapViewOfSection(sectionHandle, process, &viewAddr, 0, NULL, NULL, &viewSize, (SECTION_INHERIT)2, NULL, protect);
	return viewAddr;
}