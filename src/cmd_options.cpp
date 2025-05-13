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

constexpr std::string_view kOptStrHelp = "help";
constexpr std::string_view kOptStrInput = "input";
constexpr std::string_view kOptStrOutput = "output";
constexpr std::string_view kOptStrPassword = "password";

constexpr std::string_view kOptStrCommand = "command";
constexpr std::string_view kOptStrCommandEncrypt = "encrypt";
constexpr std::string_view kOptStrCommandDecrypt = "decrypt";
constexpr std::string_view kOptStrCommandChecksum = "checksum";

ProgramOptions::ProgramOptions() : desc_("Allowed options") { SetupOptions(); }

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map variablesMap;
    try {
        po::store(po::parse_command_line(argc, argv, desc_), variablesMap);
        po::notify(variablesMap);
    } catch (const boost::exception &exc) {
        throw std::runtime_error(boost::diagnostic_information(exc));
    }
    if (variablesMap.contains(kOptStrHelp.data())) {
        std::cout << desc_;
    }
    return true;
}

void ProgramOptions::SetupOptions() {
    desc_.add_options()(kOptStrHelp.data(), "prints this help message")(
        kOptStrInput.data(),
        po::value<std::string>()->default_value("./input.txt")->composing()->notifier([this](std::string inputFile) {
            NotifierInputFile(std::move(inputFile));
        }),
        "input file path")(
        kOptStrOutput.data(),
        po::value<std::string>()->default_value("./output.txt")->composing()->notifier([this](std::string outputFile) {
            NotifierOutputFile(std::move(outputFile));
        }),
        "output file path")(kOptStrCommand.data(),
                            po::value<std::string>()->composing()->notifier(
                                [this](std::string command) { NotifierCommand(std::move(command)); }),
                            "specifies command to execute")(
        kOptStrPassword.data(), po::value<std::string>()->composing()->notifier([this](std::string password) {
            NotifierPassword(std::move(password));
        }),
        "sets encryption password");
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

void ProgramOptions::NotifierInputFile(std::string inputFile) {
    if (inputFile.empty()) {
        throw std::runtime_error("input file path is empty");
    }
    inputFile_ = std::move(inputFile);
}

void ProgramOptions::NotifierOutputFile(std::string outputFile) {
    if (outputFile.empty()) {
        throw std::runtime_error("output file path is empty");
    }
    outputFile_ = std::move(outputFile);
}

void ProgramOptions::NotifierPassword(std::string password) {
    if (password.empty()) {
        throw std::runtime_error("password is empty");
    }
    password_ = std::move(password);
}
