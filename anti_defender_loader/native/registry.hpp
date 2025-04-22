#pragma once
#include <string>
#include <winreg.h>

namespace native {
    class Registry {
    public:
        constexpr Registry() = default;

        explicit Registry(HKEY key): key_(key) { }

        Registry(HKEY key, LPCSTR subkey) {
            RegOpenKeyA(key, subkey, &key_);
        }

        ~Registry() {
            clear();
        }

        Registry& operator=(Registry&& inst) noexcept {
            this->clear();
            this->key_ = inst.key_;
            inst.reset();
            return *this;
        }

    public:
        [[nodiscard]] Registry create_key(const std::string_view path) {
            HKEY key = {};
            DWORD disposition = 0;

            const auto status = RegCreateKeyExA(key_, path.data(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, &disposition);
            if (status != S_OK) {
                std::abort();
            }

            return Registry{key};
        }

    public:
        template <typename Ty>
        bool set_value(const std::wstring_view name, Ty* value, const std::size_t length = sizeof(Ty)) {
            auto type = REG_SZ;
            if constexpr (std::is_same_v<Ty, std::uint32_t>) {
                type = REG_DWORD;
            }

            return !static_cast<bool>(
                RegSetValueExW(key_, name.data(), 0, type, reinterpret_cast<const BYTE*>(value), static_cast<DWORD>(length) * sizeof(Ty)));
        }

        void delete_key(const std::string_view path) {
            RegDeleteTreeA(key_, path.data());
        }

    public:
        explicit operator bool() {
            return static_cast<bool>(key_);
        }

        void clear() {
            if (key_)
                RegCloseKey(key_);
        }

        void reset() noexcept {
            key_ = {};
        }

    private:
        HKEY key_ = {};
    };
} // namespace native