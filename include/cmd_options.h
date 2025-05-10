#pragma once

#include <boost/program_options.hpp>
#include <string>

namespace CryptoGuard {

class ProgramOptions {
public:
    enum class COMMAND_TYPE { NONE = -1, ENCRYPT, DECRYPT, CHECKSUM, COUNT };

    ProgramOptions();
    ~ProgramOptions() = default;

    bool Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    const std::string &GetInputFile() const { return inputFile_; }
    const std::string &GetOutputFile() const { return outputFile_; }
    const std::string &GetPassword() const { return password_; }

private:
    void SetupOptions();

    void NotifierCommand(std::string);
    void NotifierInputFile(std::string);
    void NotifierOutputFile(std::string);
    void NotifierPassword(std::string);

    COMMAND_TYPE command_ = COMMAND_TYPE::NONE;

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
