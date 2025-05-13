#include <cmd_options.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace CryptoGuard;

TEST(ProgramOptionsTests, TestParseHelp){
    ProgramOptions opts;

    constexpr int argc = 2;
    std::array<const char*, argc> argv = {"", "--help"};

    ASSERT_NO_THROW(opts.Parse(argc, (char**)argv.data()));
    ASSERT_EQ(opts.GetCommand(), static_cast<ProgramOptions::COMMAND_TYPE>(-1));
    ASSERT_EQ(opts.GetInputFile(), "");
    ASSERT_EQ(opts.GetOutputFile(), "output.txt");
    ASSERT_EQ(opts.GetPassword(), "");
}

TEST(ProgramOptionsTests, TestParseCommandFail) {
    ProgramOptions opts;

    constexpr int argc = 2;
    std::array<const char*, argc> argv = {"", "--command"};

    ASSERT_THROW(opts.Parse(argc, (char**)argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTests, TestParseCommandSuccess) {
    ProgramOptions opts;

    constexpr int argc = 3;
    std::array<const char*, argc> argv = {"", "--command", "encrypt"};

    ASSERT_NO_THROW(opts.Parse(argc, (char**)argv.data()));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);

    argv = {"", "--command", "decrypt"};

    ASSERT_NO_THROW(opts.Parse(argc, (char**)argv.data()));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);

    argv = {"", "--command", "checksum"};

    ASSERT_NO_THROW(opts.Parse(argc, (char**)argv.data()));
    ASSERT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptionsTests, TestParseInputFile) {
    ProgramOptions opts;

    constexpr int argc = 3;
    std::array<const char*, argc> argv = {"", "--input", "some in path"};

    ASSERT_NO_THROW(opts.Parse(argc, (char**)argv.data()));
    ASSERT_EQ(opts.GetInputFile(), "some in path");
}

TEST(ProgramOptionsTests, TestParseOutputFile) {
    ProgramOptions opts;

    constexpr int argc = 3;
    std::array<const char*, argc> argv = {"", "--output", "some out path"};

    ASSERT_NO_THROW(opts.Parse(argc, (char**)argv.data()));
    ASSERT_EQ(opts.GetOutputFile(), "some out path");
}

TEST(ProgramOptionsTests, TestParseUnrecognized) {
    ProgramOptions opts;

    constexpr int argc = 2;
    std::array<const char*, argc> argv = {"", "--unrecognized"};

    ASSERT_THROW(opts.Parse(argc, (char**)argv.data()), std::runtime_error);
}
