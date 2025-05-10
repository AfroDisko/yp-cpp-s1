#include <cmd_options.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace CryptoGuard;

namespace {
std::string optNone = "";
std::string optHelp = "--help";

std::string optCommand = "--command";
std::string optEncrypt = "encrypt";
std::string optDecrypt = "decrypt";
std::string optChecksum = "checksum";

std::string optInput = "--input";
std::string optOutput = "--output";
std::string optPath= "test.txt";
}

TEST(ProgramOptionsTests, TestParseHelp){
    ProgramOptions opts;

    constexpr int argc = 2;
    char* argv[argc] = {};

    argv[0] = optNone.data();
    argv[1] = optHelp.data();

    ASSERT_NO_THROW(opts.Parse(argc, argv));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::NONE);
    ASSERT_EQ(opts.GetInputFile(), "./input.txt");
    ASSERT_EQ(opts.GetOutputFile(), "./output.txt");
    ASSERT_EQ(opts.GetPassword(), "");
}

TEST(ProgramOptionsTests, TestParseCommandFail) {
    ProgramOptions opts;

    constexpr int argc = 2;
    char* argv[argc] = {};

    argv[0] = optNone.data();
    argv[1] = optCommand.data();

    ASSERT_THROW(opts.Parse(argc, argv), std::runtime_error);
}

TEST(ProgramOptionsTests, TestParseCommandSuccess) {
    ProgramOptions opts;

    constexpr int argc = 3;
    char* argv[argc] = {};

    argv[0] = optNone.data();
    argv[1] = optCommand.data();
    argv[2] = optEncrypt.data();

    ASSERT_NO_THROW(opts.Parse(argc, argv));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);

    argv[2] = optDecrypt.data();

    ASSERT_NO_THROW(opts.Parse(argc, argv));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);

    argv[2] = optChecksum.data();

    ASSERT_NO_THROW(opts.Parse(argc, argv));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptionsTests, TestParseInputFile) {
    ProgramOptions opts;

    constexpr int argc = 3;
    char* argv[argc] = {};

    argv[0] = optNone.data();
    argv[1] = optInput.data();
    argv[2] = optPath.data();

    ASSERT_NO_THROW(opts.Parse(argc, argv));
    ASSERT_EQ(opts.GetInputFile(), optPath);
}

TEST(ProgramOptionsTests, TestParseOutputFile) {
    ProgramOptions opts;

    constexpr int argc = 3;
    char* argv[argc] = {};

    argv[0] = optNone.data();
    argv[1] = optOutput.data();
    argv[2] = optPath.data();

    ASSERT_NO_THROW(opts.Parse(argc, argv));
    ASSERT_EQ(opts.GetOutputFile(), optPath);
}

TEST(ProgramOptionsTests, TestParseUnrecognized) {
    ProgramOptions opts;

    constexpr int argc = 2;
    char* argv[argc] = {};

    std::string optUnrecognized = "--unrecoginzed";

    argv[0] = optNone.data();
    argv[1] = optUnrecognized.data();

    ASSERT_THROW(opts.Parse(argc, argv), std::runtime_error);
}

TEST(ProgramOptionsTests, TestParseInvalid) {
    ProgramOptions opts;

    constexpr int argc = 3;
    char* argv[argc] = {};

    std::string optInvalid = "";

    argv[0] = optNone.data();
    argv[1] = optInput.data();
    argv[2] = optInvalid.data();

    ASSERT_THROW(opts.Parse(argc, argv), std::runtime_error);
}
