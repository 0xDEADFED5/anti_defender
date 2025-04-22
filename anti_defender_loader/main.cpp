#include <cassert>
#include <cstdint>
#include <format>
#include <iostream>
#include <Windows.h>
#include <thread>
#include "native/registry.hpp"
#include "native/service_loader.hpp"
#include "util.hpp"

#include <argparse/argparse.hpp>
#include <shared/structs.hpp>

namespace {
    void setup_registry() {
        auto reg = native::Registry(HKEY_LOCAL_MACHINE, "SOFTWARE");
        reg = reg.create_key("Avast Software");
        reg = reg.create_key("Avast");
        (void)reg.create_key("properties");

        const auto path = util::app_path().parent_path().wstring();
        const bool status = reg.set_value(L"ProgramFolder", path.c_str(), path.length());
        if (!status) {
            throw std::runtime_error("unable to init registry, are we really elevated?");
        }
    }

    void start(service_loader::Instance& loader) {
        auto wsc_proxy = util::app_path().parent_path();
        wsc_proxy /= "wsc_proxy.exe";

        std::cout << "** loading the wsc_proxy" << std::endl;
        auto svc = loader.create_and_start_um_service("wsc_proxy", "wsc_proxy", std::format("\"{}\" /runassvc /rpcserver", wsc_proxy.string()));
        if (!svc.has_value()) {
            throw std::runtime_error("unable to load wsc_proxy");
        }

        std::cout << "** waiting for wsc_proxy (this could take some time)" << std::endl;
        while (util::process_exists(wsc_proxy.filename().wstring())) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void remove_service(service_loader::Instance& loader) {
        std::cout << "** removing the service" << std::endl;
        auto svc = loader.open_service("wsc_proxy");
        if (!svc.has_value()) {
            throw std::runtime_error("unable to open wsc_proxy");
        }

        if (!loader.stop_and_delete_service(svc.value())) {
            throw std::runtime_error("unable to remove wsc_proxy");
        }
    }
} // namespace

int main(int argc, char* argv[]) try {
    argparse::ArgumentParser program("anti_defender_loader", "1.0.2");
    program.add_argument("--disable").help("disable the anti_defender stuff").flag();
    program.add_argument("--name").help("av name").default_value(std::string("github.com/0xDEADFED5/anti_defender")).nargs(1);
    program.parse_args(argc, argv);

    auto name = program.get<std::string>("--name");
    if (name.length() > shared::kMaxNameLength) {
        throw std::runtime_error(std::format("Max name length is {} characters", shared::kMaxNameLength));
    }

    shared::init_ctx_t ctx = {};
    ctx.state = program.get<bool>("--disable") == true ? shared::e_state::OFF : shared::e_state::ON;
    std::ranges::copy(name, ctx.name.data());

    std::cout << "** saving the ctx.." << std::endl;
    ctx.serialize();

    std::cout << "** setting the registry keys up" << std::endl;
    setup_registry();

    if (!util::grant_privileges({L"SeLoadDriverPrivilege"})) {
        throw std::runtime_error("unable to acquire privileges");
    }

    service_loader::Instance loader = {};

    /// Invoke the wsc_proxy and let it enable/disable stuff
    start(loader);

    /// We don't want to add ourselves to autorun in that case
    if (ctx.state == shared::e_state::OFF) {
        remove_service(loader);
    } 

    std::cout << "** done! thanks for using the anti_defender project ^^" << std::endl << std::endl;
    std::cout << "** please don't forget to leave a star at https://github.com/0xDEADFED5/anti_defender" << std::endl;

    if (ctx.state == shared::e_state::ON) {
        std::cout << "** please don't remove any files from this folder, otherwise anti_defender wouldn't be activated after the reboot!" << std::endl;
        std::cout << "** if you wish to change the folder, please de-activate anti_defender, change the folder and activate it again" << std::endl;
        std::cout << "** to de-activate the anti_defender please run 'anti_defender_loader.exe --disable'" << std::endl;
    }
    std::cout << "Press any key to continue..." << std::endl << std::endl;
    std::cin.get();
    return EXIT_SUCCESS;
} catch (const std::exception& err) {
    std::cerr << err.what() << std::endl;
    std::cin.get();
    std::exit(EXIT_FAILURE);
}
