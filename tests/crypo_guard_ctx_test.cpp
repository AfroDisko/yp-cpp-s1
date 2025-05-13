#include <functional>
#include <gtest/gtest.h>

#include <crypto_guard_ctx.h>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace CryptoGuard;

namespace {
    std::string password = "password";
    std::string initialStr = "Hello OpenSSL crypto world!";
}

TEST(CryptoGuardCtxTest, TestEncrypt) {
    CryptoGuardCtx guard;

    std::stringstream in(initialStr);
    std::stringstream out;

    guard.EncryptFile(in, out, password);
    std::cout << std::format("{}\n{}\n", in.str(), out.str());
}

TEST(CryptoGuardCtxTest, TestEncryptDecrypt) {
    CryptoGuardCtx guard;

    std::stringstream in(initialStr);
    std::stringstream encrypted;
    std::stringstream decrypted;

    guard.EncryptFile(in, encrypted, password);
    guard.DecryptFile(encrypted, decrypted, password);

    auto hash1 = std::hash<std::string>{}(in.str());
    auto hash2 = std::hash<std::string>{}(decrypted.str());

    std::cout << std::format("{}\n{}\n{}\n", in.str(), encrypted.str(), decrypted.str());
    std::cout << std::format("{}\n{}\n", hash1, hash2);

    ASSERT_EQ(in.str(), decrypted.str());
    ASSERT_EQ(hash1, hash2);
}

TEST(CryptoGuardTests, TestChecksum) {
    CryptoGuardCtx guard;

    std::stringstream in(initialStr);

    std::cout << std::format("{}\n", guard.CalculateChecksum(in));
}

TEST(CryptoGuardTests, TestEncryptDecryptWithChecksum) {
    CryptoGuardCtx guard;

    std::stringstream in(initialStr);
    std::stringstream encrypted;
    std::stringstream decrypted;

    guard.EncryptFile(in, encrypted, password);
    guard.DecryptFile(encrypted, decrypted, password);

    auto hash1 = std::hash<std::string>{}(in.str());
    auto hash2 = std::hash<std::string>{}(decrypted.str());

    in = std::stringstream(initialStr);
    std::string cs1 = guard.CalculateChecksum(in);
    std::string cs2 = guard.CalculateChecksum(decrypted);

    std::cout << std::format("{}\n{}\n", in.str(), decrypted.str());
    std::cout << std::format("{}\n{}\n", hash1, hash2);
    std::cout << std::format("{}\n{}\n", cs1, cs2);

    ASSERT_EQ(in.str(), decrypted.str());   
    ASSERT_EQ(hash1, hash2);
    ASSERT_EQ(cs1, cs2);
}

TEST(CryptoGuardTests, TestStreamMissuse) {
    CryptoGuardCtx guard;

    std::stringstream in(initialStr);
    std::stringstream out;

    guard.EncryptFile(in, out, password);
    ASSERT_THROW(guard.EncryptFile(in, out, password), std::runtime_error);
}
