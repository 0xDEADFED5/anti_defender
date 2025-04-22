#pragma once
#include <string>

#include <TlHelp32.h>
#include <Windows.h>

namespace util {
    inline bool grant_privileges(const std::vector<std::wstring_view> names) {
        TOKEN_PRIVILEGES Priv, PrivOld;
        DWORD cbPriv = sizeof(PrivOld);
        HANDLE token;

        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &token)) {
            if (GetLastError() != ERROR_NO_TOKEN) {
                return false;
            }
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
                return false;
            }
        }

        Priv.PrivilegeCount = 1;
        Priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        for (auto& name : names) {
            if (!LookupPrivilegeValueW(NULL, name.data(), &Priv.Privileges[0].Luid)) {
                return false;
            }

            if (!AdjustTokenPrivileges(token, FALSE, &Priv, sizeof(Priv), &PrivOld, &cbPriv)) {
                return false;
            }
        }

        return true;
    }

    inline bool process_exists(const std::wstring_view name) {
        PROCESSENTRY32W entry = {.dwSize = sizeof(entry)};

        auto snapshot =
            std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

        if (Process32FirstW(snapshot.get(), &entry)) {
            while (Process32NextW(snapshot.get(), &entry)) {
                if (wcscmp(entry.szExeFile, name.data()) != 0) {
                    continue;
                }

                return true;
            }
        }

        return false;
    }
} // namespace util