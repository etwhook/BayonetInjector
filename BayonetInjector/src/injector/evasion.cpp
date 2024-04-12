#include "../../include/injector/injector.h";

using namespace injector;


bool evasion::setCurrentProcessIC(PVOID callBack) {
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
	nirvana.Callback = callBack;
	nirvana.Reserved = 0;
	nirvana.Version = 0;
	
	NTSTATUS status = NtSetInformationProcess(
		injector::currentProcess,
		(PROCESSINFOCLASS)0x28,
		&nirvana,
		sizeof(nirvana)
	);
	return NT_SUCCESS(status);

}

bool evasion::setProcessIC(HANDLE process, PVOID callBack) {
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
	nirvana.Callback = callBack;
	nirvana.Reserved = 0;
	nirvana.Version = 0;

	NTSTATUS status = NtSetInformationProcess(
		process,
		(PROCESSINFOCLASS)0x28,
		&nirvana,
		sizeof(nirvana)
	);
	
	printf("%x\n", status);
	return NT_SUCCESS(status);

}