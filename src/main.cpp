#include <cstdlib>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <cmd_options.h>
#include <crypto_guard_ctx.h>

using namespace CryptoGuard;

void process(const ProgramOptions &opts) {
    auto cannotOpenMessage = [](const std::string &path) { return std::format("cannot open file '{}'", path); };
    auto passwordWarning = [](const ProgramOptions &opts) {
        if (opts.GetPassword().empty())
            std::cout << "Warning: password is empty\n";
    };

    CryptoGuardCtx guard;

    switch (opts.GetCommand()) {
    case ProgramOptions::COMMAND_TYPE::NONE:
        break;
    case ProgramOptions::COMMAND_TYPE::ENCRYPT: {
        passwordWarning(opts);
        std::ifstream fileIn(opts.GetInputFile());
        if (!fileIn.is_open())
            throw std::runtime_error(cannotOpenMessage(opts.GetInputFile()));
        std::ofstream fileOut(opts.GetOutputFile());
        if (!fileOut.is_open())
            throw std::runtime_error(cannotOpenMessage(opts.GetOutputFile()));
        guard.EncryptFile(fileIn, fileOut, opts.GetPassword());
        break;
    }
    case ProgramOptions::COMMAND_TYPE::DECRYPT: {
        passwordWarning(opts);
        std::ifstream fileIn(opts.GetInputFile());
        if (!fileIn.is_open())
            throw std::runtime_error(cannotOpenMessage(opts.GetInputFile()));
        std::ofstream fileOut(opts.GetOutputFile());
        if (!fileOut.is_open())
            throw std::runtime_error(cannotOpenMessage(opts.GetOutputFile()));
        guard.DecryptFile(fileIn, fileOut, opts.GetPassword());
        break;
    }
    case ProgramOptions::COMMAND_TYPE::CHECKSUM: {
        std::ifstream fileIn(opts.GetInputFile());
        if (!fileIn.is_open())
            throw std::runtime_error(cannotOpenMessage(opts.GetInputFile()));
        std::cout << std::format("Checksum: {}\n", guard.CalculateChecksum(fileIn));
        break;
    }
    default:
        throw std::runtime_error("unexpected option");
    }
}

int main(int argc, char *argv[]) {
    try {
        ProgramOptions opts;
        if (!opts.Parse(argc, argv))
            return EXIT_FAILURE;
        process(opts);
    } catch (const std::runtime_error &exc) {
        std::cerr << std::format("Runtime error: {}\n", exc.what());
        return EXIT_FAILURE;
    } catch (const std::exception &exc) {
        std::cerr << std::format("Unexpected error: {}\n", exc.what());
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown error\n";
    }
    return EXIT_SUCCESS;
}
