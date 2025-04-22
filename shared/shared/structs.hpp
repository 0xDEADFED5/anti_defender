#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>

#include "shared/util.hpp"

namespace shared {
    constexpr std::size_t kMaxNameLength = 128;
    constexpr std::string_view kCtxPath = "ctx.bin";

    namespace detail {
        inline std::string ctx_path() {
            auto path = util::app_path().parent_path();
            path /= kCtxPath;
            return path.string();
        }
    } // namespace detail

    enum class e_state : std::uint8_t {
        ON = 0,
        OFF,
    };

    struct init_ctx_t {
    public:
        e_state state = e_state::ON;
        std::array<char, kMaxNameLength + 1> name = {0}; // +1 for the nullterm

        void serialize() const {
            std::ofstream stream(detail::ctx_path(), std::ios::binary);
            stream.write(reinterpret_cast<const char*>(this), sizeof(*this));
        }

        void deserialize() {
            std::ifstream stream(detail::ctx_path(), std::ios::binary);
            stream.read(reinterpret_cast<char*>(this), sizeof(*this));
        }
    };
    static_assert(std::is_trivially_copyable_v<init_ctx_t>);
} // namespace shared
