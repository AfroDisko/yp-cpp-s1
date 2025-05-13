#include <cstdlib>
#include <exception>
#include <format>
#include <fstream>
#include <ios>
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
    auto openFileStream = [](const std::string &path, std::ios::openmode mode) {
        std::fstream file(path, mode);
        if (!file.is_open())
            throw std::runtime_error(std::format("cannot open file '{}'", path));
        return file;
    };

    CryptoGuardCtx guard;

    switch (opts.GetCommand()) {
    case ProgramOptions::COMMAND_TYPE::ENCRYPT: {
        passwordWarning(opts);
        std::fstream fileIn = openFileStream(opts.GetInputFile(), std::ios::in);
        std::fstream fileOut = openFileStream(opts.GetOutputFile(), std::ios::out);
        guard.EncryptFile(fileIn, fileOut, opts.GetPassword());
        break;
    }
    case ProgramOptions::COMMAND_TYPE::DECRYPT: {
        passwordWarning(opts);
        std::fstream fileIn = openFileStream(opts.GetInputFile(), std::ios::in);
        std::fstream fileOut = openFileStream(opts.GetOutputFile(), std::ios::out);
        guard.DecryptFile(fileIn, fileOut, opts.GetPassword());
        break;
    }
    case ProgramOptions::COMMAND_TYPE::CHECKSUM: {
        std::fstream fileIn = openFileStream(opts.GetInputFile(), std::ios::in);
        std::print(std::cout, "Checksum: {}\n", guard.CalculateChecksum(fileIn));
        break;
    }
    default:
        break;
    }
}

int main(int argc, char *argv[]) {
    try {
        ProgramOptions opts;
        if (!opts.Parse(argc, argv))
            return EXIT_FAILURE;
        process(opts);
    } catch (const std::runtime_error &exc) {
        std::print(std::cerr, "Runtime error: {}\n", exc.what());
        return EXIT_FAILURE;
    } catch (const std::exception &exc) {
        std::print(std::cerr, "Unexpected error: {}\n", exc.what());
        return EXIT_FAILURE;
    } catch (...) {
        std::print(std::cerr, "Unknown error\n");
    }
    return EXIT_SUCCESS;
}
