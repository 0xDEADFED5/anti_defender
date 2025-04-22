#pragma once
#include "registry.hpp"
//#include <iostream>
//#include <fstream>
#include <expected>
#include <filesystem>
#include <memory>
#include <winternl.h>

namespace service_loader {
    using error_t = std::monostate;

    class Instance {
    public:
        using handle_t = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, decltype(&CloseServiceHandle)>;

        Instance(): _handle(handle_t(OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS), &CloseServiceHandle)) { }

        [[nodiscard]] std::expected<handle_t, error_t> create_and_start_um_service(const std::string_view name, const std::string_view display_name,
                                                                                   const std::string& path) {
            auto result = CreateServiceA(_handle.get(), name.data(), display_name.data(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, path.data(), nullptr, nullptr, nullptr, nullptr, nullptr);
            /*std::ofstream logFile("log.txt", std::ios::app);
            logFile << "service created, GetLastError = " << std::hex << GetLastError() << std::endl;
            logFile.close();*/
            if (result == nullptr) {
                result = OpenServiceA(_handle.get(), name.data(), SERVICE_ALL_ACCESS);
            }

            if (result == nullptr) {
                /*std::ofstream logFile("log.txt", std::ios::app);
                logFile << "unable to open service, GetLastError = " << std::hex << GetLastError() << std::endl;
                logFile.close();*/
                return std::unexpected(error_t{});
            }

            if (!static_cast<bool>(StartServiceA(result, 0, nullptr)) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                return std::unexpected(error_t{});
            }

            return handle_t(result, &CloseServiceHandle);
        }

        [[nodiscard]] std::expected<handle_t, error_t> open_service(const std::string_view name) {
            auto result = OpenServiceA(_handle.get(), name.data(), SERVICE_ALL_ACCESS);
            if (result == nullptr) {
                return std::unexpected(error_t{});
            }

            return handle_t(result, &CloseServiceHandle);
        }

        bool stop_and_delete_service(handle_t& service) {
            SERVICE_STATUS status = {};
            ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
            return static_cast<bool>(DeleteService(service.get()));
        }

    private:
        handle_t _handle;
    };
} // namespace service_loader
