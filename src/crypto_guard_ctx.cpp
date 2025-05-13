#include "crypto_guard_ctx.h"

#include <array>
#include <cstddef>
#include <format>
#include <iomanip>
#include <ios>
#include <iostream>
#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <openssl/err.h>
#include <openssl/evp.h>

using namespace CryptoGuard;

struct AesCipherParams {
    // AES-256 key size
    static constexpr std::size_t KEY_SIZE = 32;
    // AES block size (IV length)
    static constexpr std::size_t IV_SIZE = 16;
    // Encryption key
    std::array<unsigned char, KEY_SIZE> key;
    // Initialization vector
    std::array<unsigned char, IV_SIZE> iv;
    // Cipher algorithm
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    // 1 for encryption, 0 for decryption
    int encrypt = ENCRYPT;
    enum Action : decltype(encrypt) { ENCRYPT = 1, DECRYPT = 0 };
};

class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();

    void Encrypt(std::istream &, std::ostream &, std::string_view);
    void Decrypt(std::istream &, std::ostream &, std::string_view);
    std::string CalculateChecksum(std::istream &);

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view) const;
    void Process(std::istream &, std::ostream &, AesCipherParams &);
    std::string GetLatestError() const;

    struct CipherCtxDeleter {
        void operator()(EVP_CIPHER_CTX *ctx) const {
            if (!!ctx)
                EVP_CIPHER_CTX_free(ctx);
        }
    };
    struct MdCtxDeleter {
        void operator()(EVP_MD_CTX *ctx) const {
            if (!!ctx)
                EVP_MD_CTX_free(ctx);
        }
    };

    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctxCipher_;
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctxMd_;
};

CryptoGuardCtx::Impl::Impl() {
    OpenSSL_add_all_algorithms();
    ctxCipher_.reset(EVP_CIPHER_CTX_new());
    if (!ctxCipher_)
        throw std::runtime_error(std::format("cannot initialize cipher context: {}", GetLatestError()));
    ctxMd_.reset(EVP_MD_CTX_new());
    if (!ctxMd_)
        throw std::runtime_error(std::format("cannot initialize md context: {}", GetLatestError()));
}

CryptoGuardCtx::Impl::~Impl() {
    ctxMd_.reset();
    ctxCipher_.reset();
    EVP_cleanup();
}

void CryptoGuardCtx::Impl::Encrypt(std::istream &in, std::ostream &out, std::string_view password) {
    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = AesCipherParams::ENCRYPT;

    Process(in, out, params);
}

void CryptoGuardCtx::Impl::Decrypt(std::istream &in, std::ostream &out, std::string_view password) {
    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = AesCipherParams::DECRYPT;

    Process(in, out, params);
}

void CryptoGuardCtx::Impl::Process(std::istream &in, std::ostream &out, AesCipherParams &params) {
    static constexpr std::size_t blockSize = 1024;

    if (!in || !out)
        throw std::runtime_error("bad stream passed");

    std::array<unsigned char, blockSize> bufferIn = {};
    auto *bufferInPtr = reinterpret_cast<char *>(bufferIn.data());
    int bufferInLen = 0;

    std::array<unsigned char, blockSize + EVP_MAX_BLOCK_LENGTH> bufferOut = {};
    auto *bufferOutPtr = reinterpret_cast<char *>(bufferOut.data());
    int bufferOutLen = 0;

    int retval = EVP_CipherInit_ex(ctxCipher_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                                   params.encrypt);
    if (retval == 0)
        throw std::runtime_error(std::format("cannot initialize cipher: {}", GetLatestError()));

    while (in && out) {
        bufferInLen = static_cast<int>(in.read(bufferInPtr, bufferIn.size()).gcount());
        // std::clog << std::format("read {} bytes\n", bufferInLen);

        retval = EVP_CipherUpdate(ctxCipher_.get(), bufferOut.data(), &bufferOutLen, bufferIn.data(), bufferInLen);
        if (retval == 0)
            throw std::runtime_error(std::format("cannot update cipher: {}", GetLatestError()));

        out.write(bufferOutPtr, bufferOutLen);
        // std::clog << std::format("wrote {} bytes\n", bufferOutLen);
    }

    retval = EVP_CipherFinal_ex(ctxCipher_.get(), bufferOut.data(), &bufferOutLen);
    if (retval == 0)
        throw std::runtime_error(std::format("cannot finalize cipher: {}", GetLatestError()));
    out.write(bufferOutPtr, bufferOutLen);

    EVP_CIPHER_CTX_cleanup(ctxCipher_.get());
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::istream &in) {
    static constexpr std::size_t blockSize = 1024;

    if (!in)
        throw std::runtime_error("bad stream passed");

    std::array<unsigned char, blockSize> buffer = {};
    auto *bufferPtr = reinterpret_cast<char *>(buffer.data());
    int bufferLen = 0;

    std::array<unsigned char, EVP_MAX_MD_SIZE> md = {};
    auto *mdPtr = reinterpret_cast<char *>(md.data());
    unsigned int mdLen = 0;

    int retval = EVP_DigestInit_ex(ctxMd_.get(), EVP_sha256(), nullptr);
    if (retval == 0)
        throw std::runtime_error(std::format("cannot initialize md: {}", GetLatestError()));

    while (in) {
        bufferLen = static_cast<int>(in.read(bufferPtr, buffer.size()).gcount());
        // std::clog << std::format("read {} bytes\n", bufferLen);

        retval = EVP_DigestUpdate(ctxMd_.get(), buffer.data(), bufferLen);
        if (retval == 0)
            throw std::runtime_error(std::format("cannot update md: {}", GetLatestError()));
    }

    retval = EVP_DigestFinal_ex(ctxMd_.get(), md.data(), &mdLen);
    if (retval == 0)
        throw std::runtime_error(std::format("cannot finalize md: {}", GetLatestError()));

    std::stringstream stream;
    stream << std::hex;

    for (auto idx = 0; idx < mdLen; ++idx)
        stream << std::setw(2) << std::setfill('0') << static_cast<int>(md[idx]);

    return stream.str();
}

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) const {
    AesCipherParams params;

    int retval =
        EVP_BytesToKey(params.cipher, EVP_sha256(), nullptr, reinterpret_cast<const unsigned char *>(password.data()),
                       password.size(), 1, params.key.data(), params.iv.data());
    if (retval == 0)
        throw std::runtime_error(std::format("cannot create password key: {}", GetLatestError()));

    return params;
}

std::string CryptoGuardCtx::Impl::GetLatestError() const {
    static constexpr std::size_t maxMessageSize = 512;

    std::string message;
    message.resize(maxMessageSize);

    ERR_error_string_n(ERR_get_error(), message.data(), maxMessageSize);

    return message;
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &in, std::ostream &out, std::string_view password) {
    pImpl_ ? pImpl_->Encrypt(in, out, password) : throw std::runtime_error("nullptr pimpl");
}

void CryptoGuardCtx::DecryptFile(std::istream &in, std::ostream &out, std::string_view password) {
    pImpl_ ? pImpl_->Decrypt(in, out, password) : throw std::runtime_error("nullptr pimpl");
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &in) {
    return pImpl_ ? pImpl_->CalculateChecksum(in) : throw std::runtime_error("nullptr pimpl");
}
