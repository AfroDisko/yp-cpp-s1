#include "cmd_options.h"

#include <boost/exception/diagnostic_information.hpp>
#include <boost/exception/exception.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace CryptoGuard;

namespace po = boost::program_options;

namespace {

const char *kOptStrHelp = "help";
const char *kOptStrInput = "input";
const char *kOptStrOutput = "output";
const char *kOptStrPassword = "password";

const char *kOptStrCommand = "command";
const char *kOptStrCommandEncrypt = "encrypt";
const char *kOptStrCommandDecrypt = "decrypt";
const char *kOptStrCommandChecksum = "checksum";

}  // namespace

ProgramOptions::ProgramOptions() : desc_("Allowed options") { SetupOptions(); }

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map variablesMap;
    try {
        po::store(po::parse_command_line(argc, argv, desc_), variablesMap);
        po::notify(variablesMap);
    } catch (const std::exception &exc) {
        throw std::runtime_error(exc.what());
    }
    if (variablesMap.contains(kOptStrHelp)) {
        std::cout << desc_;
    }
    return true;
}

void ProgramOptions::SetupOptions() {
    auto wrapperCommand = [this](std::string command) { NotifierCommand(std::move(command)); };

    // clang-format off
    desc_.add_options()
    (kOptStrHelp, "prints this help message")
    (kOptStrInput, po::value<std::string>(&inputFile_), "input file path")
    (kOptStrOutput, po::value<std::string>(&outputFile_)->default_value("output.txt"), "output file path")
    (kOptStrCommand, po::value<std::string>()->notifier(wrapperCommand), "specifies command to execute")
    (kOptStrPassword, po::value<std::string>(&password_), "sets encryption password");
    // clang-format on
}

void ProgramOptions::NotifierCommand(std::string command) {
    static const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping = {
        {kOptStrCommandEncrypt, ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {kOptStrCommandDecrypt, ProgramOptions::COMMAND_TYPE::DECRYPT},
        {kOptStrCommandChecksum, ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    auto it = commandMapping.find(command);
    if (it == commandMapping.end()) {
        throw std::runtime_error(std::format("unrecognized command '{}'", command));
    }
    command_ = it->second;
}
