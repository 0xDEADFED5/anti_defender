#pragma once
#include <cstdint>
#include <shared/structs.hpp>

namespace globals {
    /// <summary>
    /// Base address of the original `powrprof.dll` module
    /// </summary>
    inline std::uintptr_t powrprof_base = 0;

    /// <summary>
    /// Base address of the avast's wsc.dll module
    /// </summary>
    inline std::uintptr_t wsc_base = 0;

    /// <summary>
    /// Address of RPC target A
    /// </summary>
    inline std::uintptr_t wsc_rpc_a = 0;

    /// <summary>
    /// Address of RPC target B
    /// </summary>
    inline std::uintptr_t wsc_rpc_b = 0;

    /// <summary>
    /// Address of RPC update hook
    /// </summary>
    inline std::uintptr_t wsc_rpc_update = 0;

    /// <summary>
    /// Address of proceed hook
    /// </summary>
    inline std::uintptr_t wsc_proceed = 0;

    /// <summary>
    /// Address of process item hook
    /// </summary>
    inline std::uintptr_t wsc_process = 0;

    /// <summary>
    /// Address of wait target
    /// </summary>
    inline std::uintptr_t wsc_wait = 0;

    /// <summary>
    /// Would be set to true once the item is processed
    /// </summary>
    inline std::atomic_bool processed = false;

    /// <summary>
    /// Shared initialization context
    /// </summary>
    inline shared::init_ctx_t init_ctx = {};
} // namespace globals
