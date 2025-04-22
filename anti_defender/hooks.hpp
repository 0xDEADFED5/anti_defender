#pragma once
#include <cassert>

#include "globals.hpp"
#include "MinHook.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#if defined(NDEBUG)
    #undef assert // thx msvc stl for the superior optimizations
    #define assert(expression) ((void)(expression))
#endif

namespace hooks {
    namespace original {
        inline decltype(&::CreateFileW) CreateFileW = nullptr;
        inline decltype(&::DeviceIoControl) DeviceIoControl = nullptr;
        inline decltype(&::I_RpcBindingInqLocalClientPID) I_RpcBindingInqLocalClientPID = nullptr;
        inline decltype(&::WaitForSingleObject) WaitForSingleObject = nullptr;
        inline void* ProceedQueue = nullptr;
        inline void* ProcessItem = nullptr;
    } // namespace original

    namespace hooked {
        std::uintptr_t ProceedQueue() {

            auto payload =
                std::format(L"/svc /update /av_as /state:{} /signatures:up_to_date", globals::init_ctx.state == shared::e_state::ON ? L"on" : L"off");

            using s_wscrpc_update_t = void (*)(const wchar_t* command, const bool async);
            reinterpret_cast<s_wscrpc_update_t>(globals::wsc_rpc_update)(payload.data(), true);
            // reinterpret_cast<s_wscrpc_update_t>(globals::wsc_base + 0x2A120)(payload.data(), true);

            const auto result = reinterpret_cast<decltype(&ProceedQueue)>(original::ProceedQueue)();
            std::exit(0); // just in case we didn't exit through the `WaitForSingleObject` hook
            return result;
        }

        __int64 ProcessItem(__int64 pthis) {
            globals::processed = false;

            auto result = reinterpret_cast<decltype(&ProcessItem)>(original::ProcessItem)(pthis);

            globals::processed = true;
            return result;
        }

        HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                  DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
            auto file_path = std::wstring(lpFileName);

            std::ranges::transform(file_path.begin(), file_path.end(), file_path.begin(),
                                   [](const auto ch) -> wchar_t { return static_cast<wchar_t>(std::tolower(static_cast<int>(ch))); });

            if (file_path.find(L"asw") != std::wstring::npos) {
                static std::once_flag fl;
                std::call_once(fl, []() -> void {
                    // globals::wsc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("wsc"));

                    /*MH_CreateHook(reinterpret_cast<void*>(globals::wsc_base + 0x29C80), ProceedQueue, &original::ProceedQueue);
                    MH_CreateHook(reinterpret_cast<void*>(globals::wsc_base + 0x29BA0), ProcessItem, &original::ProcessItem);*/
                    MH_CreateHook(reinterpret_cast<void*>(globals::wsc_proceed), ProceedQueue, &original::ProceedQueue);
                    MH_CreateHook(reinterpret_cast<void*>(globals::wsc_process), ProcessItem, &original::ProcessItem);
                    MH_EnableHook(nullptr);
                });

                return reinterpret_cast<HANDLE>(1337);
            }

            return original::CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                                         hTemplateFile);
        }

        BOOL WINAPI DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer,
                                    DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
            const auto ret =
                original::DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

            if (reinterpret_cast<uint64_t>(hDevice) != 1337) {
                return ret;
            }

            switch (dwIoControlCode) {
            case 0xB2D601C0:
                return TRUE;
            case 0xB2D600CC:
                *reinterpret_cast<int*>(lpOutBuffer) = 1;
                return TRUE;
            case 0xb2d60190:
                *reinterpret_cast<int*>(lpOutBuffer) = 1337;
                *reinterpret_cast<int*>(lpBytesReturned) = 4;
                return TRUE;
            /*case 0x70020:
                return FALSE;*/
            default:
                return ret;
            }
        }

        RPC_STATUS RPC_ENTRY I_RpcBindingInqLocalClientPID(RPC_BINDING_HANDLE Binding, unsigned long* Pid) {
            *Pid = GetCurrentProcessId();

            auto name_wstr = std::wstring(globals::init_ctx.name.data(), globals::init_ctx.name.data() + strlen(globals::init_ctx.name.data()));

            using init_str_t = void (*)(std::uintptr_t, const wchar_t*, const std::size_t);
            reinterpret_cast<init_str_t>(globals::wsc_rpc_a)(globals::wsc_rpc_b, name_wstr.data(), name_wstr.length());
            // reinterpret_cast<init_str_t>(globals::wsc_base + 0x10020)(globals::wsc_base + 0x37EFA0, name_wstr.data(), name_wstr.length());
            return 0;
        }

        DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
            if (globals::wsc_base != 0 && hHandle == *reinterpret_cast<HANDLE*>(globals::wsc_wait)) {
                // if (globals::wsc_base != 0 && hHandle == *reinterpret_cast<HANDLE*>(globals::wsc_base + 0x3F94F8)) {
                if (globals::processed) {
                    std::exit(0);
                }
            }
            return original::WaitForSingleObject(hHandle, dwMilliseconds);
        }
    } // namespace hooked

    namespace detail {
        template <typename Ty>
        [[nodiscard]] MH_STATUS create_hook(Ty function, Ty detour, Ty* original) {
            return MH_CreateHook(function, detour, reinterpret_cast<void**>(original));
        }
    } // namespace detail

    uint8_t* FindWildcardOffset(uint8_t* sigBuffer, size_t sigLen, uint8_t* buffer, uint32_t bufferLen, uint8_t wildCard) {
        bool found = false;
        for (uint32_t x = 0; x < bufferLen - sigLen; x++) {
            for (uint32_t y = 0; y < sigLen; y++) {
                if (sigBuffer[y] == wildCard || buffer[x + y] == sigBuffer[y])
                    found = true;
                else {
                    found = false;
                    break;
                }
            }
            if (found) {
                return buffer + x;
            }
        }
        return 0;
    }

    uint8_t* FindSignatureOffset(uint8_t* sigBuffer, size_t sigLen, uint8_t* buffer, uint32_t bufferLen) {
        bool found = false;
        for (uint32_t x = 0; x < bufferLen - sigLen; x++) {
            for (uint32_t y = 0; y < sigLen; y++) {
                if (buffer[x + y] == sigBuffer[y]) {
                    found = true;
                } else {
                    found = false;
                    break;
                }
            }
            if (found) {
                return buffer + x;
            }
        }
        return 0;
    }

    bool FindRPCUpdate() {
        // we need address 7FFF383CA120
        // 00007FFF383CA11F | CC                        | int3                                   |
        // 00007FFF383CA120 | 885424 10                 | mov byte ptr ss:[rsp+10],dl            |
        // 00007FFF383CA124 | 48:894C24 08              | mov qword ptr ss:[rsp+8],rcx           |
        // 00007FFF383CA129 | 55                        | push rbp                               |
        // 00007FFF383CA12A | 53                        | push rbx                               |
        // 00007FFF383CA12B | 48:8DAC24 38FFFFFF        | lea rbp,qword ptr ss:[rsp-C8]          |
        // 00007FFF383CA133 | 48:81EC C8010000          | sub rsp,1C8                            |
        // 00007FFF383CA13A | 48:8B05 BF403500          | mov rax,qword ptr ds:[7FFF3871E200]    |
        // 00007FFF383CA141 | 48:33C4                   | xor rax,rsp                            |
        // 00007FFF383CA144 | 48:8985 B0000000          | mov qword ptr ss:[rbp+B0],rax          |
        // 00007FFF383CA14B | 48:8B95 E0000000          | mov rdx,qword ptr ss:[rbp+E0]          |
        // 00007FFF383CA152 | 48:8D4D 50                | lea rcx,qword ptr ss:[rbp+50]          |
        // 00007FFF383CA156 | 0F57C0                    | xorps xmm0,xmm0                        |
        // 00007FFF383CA159 | 48:89B424 F0010000        | mov qword ptr ss:[rsp+1F0],rsi         |
        // 00007FFF383CA161 | 0FB6B5 E8000000           | movzx esi,byte ptr ss:[rbp+E8]         |
        // 00007FFF383CA168 | 33C0                      | xor eax,eax                            |
        // 00007FFF383CA16A | 45:33C0                   | xor r8d,r8d                            |
        // 00007FFF383CA16D | 48:8955 B0                | mov qword ptr ss:[rbp-50],rdx          |
        // 00007FFF383CA171 | 0F1145 50                 | movups xmmword ptr ss:[rbp+50],xmm0    |
        // 00007FFF383CA175 | 48:8985 A0000000          | mov qword ptr ss:[rbp+A0],rax          |
        // 00007FFF383CA17C | 0F1145 60                 | movups xmmword ptr ss:[rbp+60],xmm0    |
        // 00007FFF383CA180 | 0F1145 70                 | movups xmmword ptr ss:[rbp+70],xmm0    |
        // 00007FFF383CA184 | 0F1185 80000000           | movups xmmword ptr ss:[rbp+80],xmm0    |
        // 00007FFF383CA18B | 0F1185 90000000           | movups xmmword ptr ss:[rbp+90],xmm0    |
        // 00007FFF383CA192 | E8 290C0000               | call wsc.7FFF383CADC0                  |
        // 00007FFF383CA197 | F2:0F1005 D14C3500        | movsd xmm0,qword ptr ds:[7FFF3871EE70] |
        // CC 885424 ? 48894C24 ? 55 53 488DAC24 ???? 4881EC ???? 488B05 ???? 4833C4

        uint8_t sig1[] = {0xCC, 0x88, 0x54, 0x24, 0x90, 0x48, 0x89, 0x4C, 0x24, 0x90, 0x55, 0x53, 0x48, 0x8D, 0xAC, 0x24, 0x90, 0x90, 0x90,
                          0x90, 0x48, 0x81, 0xEC, 0x90, 0x90, 0x90, 0x90, 0x48, 0x8B, 0x05, 0x90, 0x90, 0x90, 0x90, 0x48, 0x33, 0xC4};
        uint8_t* p = FindWildcardOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000, 0x90);
        if (p != 0) {
            globals::wsc_rpc_update = reinterpret_cast<std::uintptr_t>(p + 1);
            return true;
        }
        return false;
    }

    bool FindRPCTargetB() {
        // we need 7FFF3871EFA0
        // 00007FFF383D9259 | 48:8B03                     | mov rax,qword ptr ds:[rbx]              |
        // 00007FFF383D925C | 4C:8B78 50                  | mov r15,qword ptr ds:[rax+50]           |
        // 00007FFF383D9260 | 4C:8D35 395D3400            | lea r14,qword ptr ds:[7FFF3871EFA0]     |
        // 00007FFF383D9267 | 48:833D 495D3400 07         | cmp qword ptr ds:[7FFF3871EFB8],7       |
        // 00007FFF383D926F | 4C:0F4735 295D3400          | cmova r14,qword ptr ds:[7FFF3871EFA0]   |
        // 00007FFF383D9277 | B9 18000000                 | mov ecx,18                              |
        // 00007FFF383D927C | E8 DFCC1D00                 | call wsc.7FFF385B5F60                   |
        // 00007FFF383D9281 | 48:8BF8                     | mov rdi,rax                             |
        // 00007FFF383D9284 | 48:894424 30                | mov qword ptr ss:[rsp+30],rax           |
        // 00007FFF383D9289 | 48:85C0                     | test rax,rax                            |
        // 00007FFF383D928C | 74 2B                       | je wsc.7FFF383D92B9                     |
        // 00007FFF383D928E | 4C:8920                     | mov qword ptr ds:[rax],r12              |
        // 00007FFF383D9291 | 48:C740 10 01000000         | mov qword ptr ds:[rax+10],1             |
        // 00007FFF383D9299 | 4C:8960 08                  | mov qword ptr ds:[rax+8],r12            |
        // 488B034C8B78 504C8D35 ????48833D ???? 07

        uint8_t sig1[] = {0x48, 0x8B, 0x03, 0x4C, 0x8B, 0x78, 0x50, 0x4C, 0x8D, 0x35, 0xCC,
                          0xCC, 0xCC, 0xCC, 0x48, 0x83, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 07};
        uint8_t* p = FindWildcardOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000, 0xCC);
        if (p != 0) {
            int32_t* rva = reinterpret_cast<int32_t*>(p + 10);
            globals::wsc_rpc_b = reinterpret_cast<std::uintptr_t>(p + *rva + 14);
            return true;
        }
        return false;
    }

    bool FindRPCTargetA() {
        // we need address 00007FFF383B0020
        // 00007FFF383B001B | CC                          | int3                              |
        // 00007FFF383B001C | CC                          | int3                              |
        // 00007FFF383B001D | CC                          | int3                              |
        // 00007FFF383B001E | CC                          | int3                              |
        // 00007FFF383B001F | CC                          | int3                              |
        // 00007FFF383B0020 | 48:8BC4                     | mov rax,rsp                       |
        // 00007FFF383B0023 | 48:8958 20                  | mov qword ptr ds:[rax+20],rbx     |
        // 00007FFF383B0027 | 4C:8940 18                  | mov qword ptr ds:[rax+18],r8      |
        // 00007FFF383B002B | 48:8950 10                  | mov qword ptr ds:[rax+10],rdx     |
        // 00007FFF383B002F | 48:8948 08                  | mov qword ptr ds:[rax+8],rcx      |
        // 00007FFF383B0033 | 55                          | push rbp                          |
        // 00007FFF383B0034 | 56                          | push rsi                          |
        // 00007FFF383B0035 | 57                          | push rdi                          |
        // 00007FFF383B0036 | 41:56                       | push r14                          |
        // 00007FFF383B0038 | 41:57                       | push r15                          |
        // 00007FFF383B003A | 48:83EC 20                  | sub rsp,20                        |
        // 00007FFF383B003E | 48:8B71 18                  | mov rsi,qword ptr ds:[rcx+18]     |
        // 00007FFF383B0042 | 48:8BF9                     | mov rdi,rcx                       |
        // 00007FFF383B0045 | 4C:8BFA                     | mov r15,rdx                       |
        // 00007FFF383B0048 | 4D:8BF0                     | mov r14,r8                        |
        // 00007FFF383B004B | 4C:3BC6                     | cmp r8,rsi                        |
        // 00007FFF383B004E | 77 2D                       | ja wsc.7FFF383B007D               |
        // 00007FFF383B0050 | 48:8BE9                     | mov rbp,rcx                       |
        // 00007FFF383B0053 | 48:83FE 07                  | cmp rsi,7                         |
        // 00007FFF383B0057 | 76 03                       | jbe wsc.7FFF383B005C              |
        // 00007FFF383B0059 | 48:8B29                     | mov rbp,qword ptr ds:[rcx]        |
        // 00007FFF383B005C | 4B:8D1C36                   | lea rbx,qword ptr ds:[r14+r14]    |
        // 00007FFF383B0060 | 4C:8977 10                  | mov qword ptr ds:[rdi+10],r14     |
        // 00007FFF383B0064 | 4C:8BC3                     | mov r8,rbx                        |
        // 488bc4488958204c8940184889501048894808555657415641574883ec20488b
        uint8_t sig1[] = {0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x4c, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50, 0x10, 0x48,
                          0x89, 0x48, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b};
        uint8_t* p = FindSignatureOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000);
        if (p != 0) {
            globals::wsc_rpc_a = reinterpret_cast<std::uintptr_t>(p);
            return true;
        }
        return false;
    }

    bool FindWaitTarget() {
        // we want 7FFF387994F8
        // 00007FFF3862C400 | 48:83EC 28                           | sub rsp,28                                    |
        // 00007FFF3862C404 | 48:8B0D EDD01600                     | mov rcx,qword ptr ds:[7FFF387994F8]           |
        // 00007FFF3862C40B | 48:85C9                              | test rcx,rcx                                  |
        // 00007FFF3862C40E | 74 06                                | je wsc.7FFF3862C416                           |
        // 00007FFF3862C410 | FF15 62130000                        | call qword ptr ds:[<&CloseHandle>]            |
        // 00007FFF3862C416 | 48:C705 D7D01600 00000000            | mov qword ptr ds:[7FFF387994F8],0             |
        // 00007FFF3862C421 | 48:83C4 28                           | add rsp,28                                    |
        // 00007FFF3862C425 | C3                                   | ret                                           |
        // 4883EC28 488B0D ???? 4885C97406FF15 ???? 48C705 ???? 00000000
        uint8_t sig1[] = {0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x85, 0xC9, 0x74, 0x06, 0xFF,
                          0x15, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xC7, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00, 0x00, 0x00};
        uint8_t* p = FindWildcardOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000, 0xCC);
        if (p != 0) {
            int32_t* rva = reinterpret_cast<int32_t*>(p + 7);
            globals::wsc_wait = reinterpret_cast<std::uintptr_t>(p + *rva + 11);
            return true;
        }
        return false;
    }

    bool FindProcessHook() {
        // we need address 7FFF383C9BA0
        // 00007FFF383C9D5F | 48:FFC9                       | dec rcx                                        |
        // 00007FFF383C9D62 | 48:230D BFF73C00              | and rcx,qword ptr ds:[7FFF38799528]            |
        // 00007FFF383C9D69 | 48:8B05 A8F73C00              | mov rax,qword ptr ds:[7FFF38799518]            |
        // 00007FFF383C9D70 | 48:8B0CC8                     | mov rcx,qword ptr ds:[rax+rcx*8]               |
        // 00007FFF383C9D74 | E8 C75AFEFF                   | call wsc.7FFF383AF840                          |
        // 00007FFF383C9D79 | 48:832D AFF73C00 01           | sub qword ptr ds:[7FFF38799530],1              |
        // 00007FFF383C9D81 | 75 09                         | jne wsc.7FFF383C9D8C                           |
        // 00007FFF383C9D83 | 48:8935 9EF73C00              | mov qword ptr ds:[7FFF38799528],rsi            |
        // 00007FFF383C9D8A | EB 07                         | jmp wsc.7FFF383C9D93                           |
        // 00007FFF383C9D8C | 48:FF05 95F73C00              | inc qword ptr ds:[7FFF38799528]                |
        // 00007FFF383C9D93 | 48:8D0D 36F73C00              | lea rcx,qword ptr ds:[7FFF387994D0]            |
        // 00007FFF383C9D9A | FF15 80392600                 | call qword ptr ds:[<&RtlLeaveCriticalSection>] |
        // 00007FFF383C9DA0 | 48:8D4F 08                    | lea rcx,qword ptr ds:[rdi+8]                   |
        // 00007FFF383C9DA4 | E8 F7FDFFFF                   | call wsc.7FFF383C9BA0                          |
        // 00007FFF383C9DA9 | 8947 60                       | mov dword ptr ds:[rdi+60],eax                  |
        // 00007FFF383C9DAC | 48:8B0F                       | mov rcx,qword ptr ds:[rdi]                     |
        // 00007FFF383C9DAF | 48:85C9                       | test rcx,rcx                                   |
        // 00007FFF383C9DB2 | 74 07                         | je wsc.7FFF383C9DBB                            |
        // 00007FFF383C9DB4 | FF15 5E392600                 | call qword ptr ds:[<&SetEvent>]                |
        // 00007FFF383C9DBA | 90                            | nop                                            |
        // 00007FFF383C9DBB | 48:85DB                       | test rbx,rbx                                   |
        // 00007FFF383C9DBE | 74 3D                         | je wsc.7FFF383C9DFD                            |
        // 00007FFF383C9DC0 | B8 FFFFFFFF                   | mov eax,FFFFFFFF                               |
        // 00007FFF383C9DC5 | F0:0FC143 08                  | lock xadd dword ptr ds:[rbx+8],eax             |
        // 00007FFF383C9DCA | 83F8 01                       | cmp eax,1                                      |
        // 00007FFF383C9DCD | 75 2E                         | jne wsc.7FFF383C9DFD                           |
        // 00007FFF383C9DCF | 48:8B03                       | mov rax,qword ptr ds:[rbx]                     |
        // 00007FFF383C9DD2 | 48:8BCB                       | mov rcx,rbx                                    |
        // 00007FFF383C9DD5 | 48:8B00                       | mov rax,qword ptr ds:[rax]                     |
        // 00007FFF383C9DD8 | FF15 0A3E2600                 | call qword ptr ds:[7FFF3862DBE8]               |
        // 00007FFF383C9DDE | B8 FFFFFFFF                   | mov eax,FFFFFFFF                               |
        // 48FF05 ???? 488D0D ???? FF15 ???? 488D4F ? E8 ???? 8947
        uint8_t sig1[] = {0x48, 0xFF, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0x15,
                          0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8D, 0x4F, 0xCC, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0x47};
        uint8_t* p = FindWildcardOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000, 0xCC);
        if (p != 0) {
            int32_t* rva = reinterpret_cast<int32_t*>(p + 25);
            globals::wsc_process = reinterpret_cast<std::uintptr_t>(p + *rva + 29);
            return true;
        }
        return false;
    }

    bool FindProceedHook() {
        // we need address 7FFF383C9C80
        // 00007FFF383CC88E | CC                              | int3                           |
        // 00007FFF383CC88F | CC                              | int3                           |
        // 00007FFF383CC890 | 48:894C24 08                    | mov qword ptr ss:[rsp+8],rcx   |
        // 00007FFF383CC895 | 48:83EC 28                      | sub rsp,28                     |
        // 00007FFF383CC899 | E8 E2D3FFFF                     | call wsc.7FFF383C9C80          |
        // 00007FFF383CC89E | E8 7D821E00                     | call wsc.7FFF385B4B20          |
        // 00007FFF383CC8A3 | 48:8B4C24 30                    | mov rcx,qword ptr ss:[rsp+30]  |
        // 00007FFF383CC8A8 | 48:85C9                         | test rcx,rcx                   |
        // 00007FFF383CC8AB | 74 0A                           | je wsc.7FFF383CC8B7            |
        // 00007FFF383CC8AD | BA 01000000                     | mov edx,1                      |
        // 00007FFF383CC8B2 | E8 69961E00                     | call wsc.7FFF385B5F20          |
        // 00007FFF383CC8B7 | 33C0                            | xor eax,eax                    |
        // 00007FFF383CC8B9 | 48:83C4 28                      | add rsp,28                     |
        // 00007FFF383CC8BD | C3                              | ret                            |
        // 00007FFF383CC8BE | CC                              | int3                           |
        // 00007FFF383CC8BF | CC                              | int3                           |
        // 48894C24 ? 4883EC ? E8 ???? E8 ???? 488B4C24 ? 4885C9 74 ? BA 01000000
        uint8_t sig1[] = {0x48, 0x89, 0x4C, 0x24, 0xCC, 0x48, 0x83, 0xEC, 0xCC, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0xCC, 0xCC,
                          0xCC, 0xCC, 0x48, 0x8B, 0x4C, 0x24, 0xCC, 0x48, 0x85, 0xC9, 0x74, 0xCC, 0xBA, 0x01, 0x00, 0x00, 0x00};
        uint8_t* p = FindWildcardOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000, 0xCC);
        if (p != 0) {
            int32_t* rva = reinterpret_cast<int32_t*>(p + 10);
            globals::wsc_proceed = reinterpret_cast<std::uintptr_t>(p + *rva + 14);
            return true;
        }
        return false;
    }

    void DoStartupPatch() {
        // this fixes wsc.dll so that it doesn't shut itself down automatically
        //00007FFF1B50437E | CC                          | int3                                   |
        //00007FFF1B50437F | CC                          | int3                                   |
        //00007FFF1B504380 | 48:895C24 18                | mov qword ptr ss:[rsp+18],rbx          |
        //00007FFF1B504385 | 48:897424 20                | mov qword ptr ss:[rsp+20],rsi          |
        //00007FFF1B50438A | 48:895424 10                | mov qword ptr ss:[rsp+10],rdx          |
        //00007FFF1B50438F | 894C24 08                   | mov dword ptr ss:[rsp+8],ecx           |
        //00007FFF1B504393 | 55                          | push rbp                               |
        //00007FFF1B504394 | 57                          | push rdi                               |
        //00007FFF1B504395 | 41:56                       | push r14                               |
        //00007FFF1B504397 | 48:8DAC24 00FEFFFF          | lea rbp,qword ptr ss:[rsp-200]         |
        //00007FFF1B50439F | 48:81EC 00030000            | sub rsp,300                            |
        //00007FFF1B5043A6 | 48:8B05 532E3400            | mov rax,qword ptr ds:[7FFF1B847200]    |
        //00007FFF1B5043AD | 48:33C4                     | xor rax,rsp                            |
        //00007FFF1B5043B0 | 48:8985 F0010000            | mov qword ptr ss:[rbp+1F0],rax         |
        //00007FFF1B5043B7 | 48:8BBD 28020000            | mov rdi,qword ptr ss:[rbp+228]         |
        //00007FFF1B5043BE | 45:33F6                     | xor r14d,r14d                          |
        //00007FFF1B5043C1 | 44:3835 A8763B00            | cmp byte ptr ds:[7FFF1B8BBA70],r14b    |
        //00007FFF1B5043C8 | 74 0D                       | je wsc_new.7FFF1B5043D7                |
        //to:
        //00007FFF1B5043C8 | EB 0D                       | jmp wsc_new.7FFF1B5043D7               |
        // 4833C4 488985 ???? 488BBD ???? 4533F6 443835 ???? 74
        uint8_t sig1[] = {0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xBD, 0xCC,
                          0xCC, 0xCC, 0xCC, 0x45, 0x33, 0xF6, 0x44, 0x38, 0x35, 0xCC, 0xCC, 0xCC, 0xCC, 0x74};
        uint8_t* p = FindWildcardOffset(sig1, sizeof(sig1), reinterpret_cast<uint8_t*>(globals::wsc_base), 0x400000, 0xCC);
        if (p != 0) {
            DWORD oldProtect;
            if (VirtualProtect(p + 27, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                p[27] = 0xEB;
                VirtualProtect(p + 27, 1, oldProtect, &oldProtect);
            } 
        }
    }

    inline void setup() {
        using namespace detail;
        assert(MH_Initialize() == MH_OK);
        globals::wsc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("wsc"));
        DoStartupPatch();
        assert(FindWaitTarget() == true);
        assert(FindRPCTargetA() == true);
        assert(FindRPCTargetB() == true);
        assert(FindProceedHook() == true);
        assert(FindProcessHook() == true);
        assert(FindRPCUpdate() == true);
        assert(create_hook(::CreateFileW, hooked::CreateFileW, &original::CreateFileW) == MH_OK);
        assert(create_hook(::DeviceIoControl, hooked::DeviceIoControl, &original::DeviceIoControl) == MH_OK);
        assert(create_hook(::I_RpcBindingInqLocalClientPID, hooked::I_RpcBindingInqLocalClientPID, &original::I_RpcBindingInqLocalClientPID) == MH_OK);
        assert(create_hook(::WaitForSingleObject, hooked::WaitForSingleObject, &original::WaitForSingleObject) == MH_OK);
        assert(MH_EnableHook(MH_ALL_HOOKS) == MH_OK);
    }
} // namespace hooks
