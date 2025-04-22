#include <cstdint>
#include <MinHook.h>
#include <shared/structs.hpp>
#include "hooks.hpp"

EXTERN_C __declspec(dllexport) NTSTATUS WINAPI CallNtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength,
                                                                      PVOID OutputBuffer, ULONG OutputBufferLength) {
    static auto orig =
        reinterpret_cast<decltype(&CallNtPowerInformation)>(GetProcAddress(reinterpret_cast<HMODULE>(globals::powrprof_base), "CallNtPowerInformation"));
    return orig(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

BOOL __stdcall DllMain(HMODULE base, std::uint32_t call_reason, std::uintptr_t reserved) {
    if (call_reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    globals::powrprof_base = reinterpret_cast<std::uintptr_t>(LoadLibraryA("c:\\Windows\\System32\\powrprof.dll"));
    assert(globals::powrprof_base != 0);

    globals::init_ctx.deserialize();
    hooks::setup();
    return TRUE;
}
