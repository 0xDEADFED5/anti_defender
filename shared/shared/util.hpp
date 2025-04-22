#include <filesystem>
#include <Windows.h>

namespace util {
    inline std::filesystem::path app_path() {
        char result[_MAX_PATH];
        GetModuleFileNameA(NULL, result, sizeof(result));
        return result;
    }
} // namespace util
