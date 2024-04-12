#pragma once
#include "../injector/injector.h"


namespace utils {

    PSYSTEM_FIRMWARE_TABLE_INFORMATION getSMBIOSHeaders() {
        ULONG dSize = 1024 * 2 * 1024 * 2;
        auto data = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)injector::memory::heapAlloc(dSize);

        data->Action = SystemFirmwareTable_Get;
        data->ProviderSignature = 'RSMB';
        data->TableBufferLength = dSize;

        NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x4C, (PVOID)data, dSize, (PULONG)&dSize);

        return data;
    }
}