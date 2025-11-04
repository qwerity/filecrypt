#pragma once

#include "result.h"

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace crypto {

constexpr std::size_t AES_256_KEY_SIZE = 32;
constexpr std::size_t AES_256_GCM_IV_SIZE = 12;
constexpr std::size_t AES_256_GCM_TAG_SIZE = 16;

using ByteBuffer = std::vector<unsigned char>;

struct SecureBuffer {
    explicit SecureBuffer(std::size_t n = 0) : buffer_(n) {}
    explicit SecureBuffer(ByteBuffer&& buffer) noexcept : buffer_(std::move(buffer)) {}
    ~SecureBuffer() noexcept { cleanse(); }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept = default;

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            cleanse();
            buffer_ = std::move(other.buffer_);
        }
        return *this;
    }

    unsigned char* data() noexcept { return buffer_.data(); }
    [[nodiscard]] const unsigned char* data() const noexcept { return buffer_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
    [[nodiscard]] bool empty() const noexcept { return buffer_.empty(); }
    void resize(std::size_t n) {
        if (n < buffer_.size()) {
            const auto offset = n;
            OPENSSL_cleanse(buffer_.data() + offset, buffer_.size() - offset);
        }
        buffer_.resize(n);
    }

    std::span<unsigned char> span() noexcept { return {buffer_.data(), buffer_.size()}; }
    [[nodiscard]] std::span<const unsigned char> span() const noexcept { return {buffer_.data(), buffer_.size()}; }

    [[nodiscard]] const ByteBuffer& bytes() const noexcept { return buffer_; }

  private:
    void cleanse() noexcept {
        if (!buffer_.empty()) {
            OPENSSL_cleanse(buffer_.data(), buffer_.size());
        }
    }

    ByteBuffer buffer_{};
};

struct EvpKeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        if (key != nullptr) {
            EVP_PKEY_free(key);
        }
    }
};
using EvpKeyPtr = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;

result::Result<EvpKeyPtr> loadPrivateKey(const std::filesystem::path& path);
result::Result<EvpKeyPtr> loadPublicKey(const std::filesystem::path& path);

result::Result<ByteBuffer> signFile(const std::filesystem::path& path, EVP_PKEY* key);
result::Result<void> verifyFileSignature(const std::filesystem::path& path, const ByteBuffer& signature, EVP_PKEY* key);

struct EncryptionResult {
    ByteBuffer iv{};
    ByteBuffer tag{};
};

result::Result<EncryptionResult> encryptFile(const std::filesystem::path& plainTextPath, const std::filesystem::path& cipherTextPath, const SecureBuffer& key);
result::Result<void> decryptFile(const std::filesystem::path& cipherTextPath, const std::filesystem::path& plainTextPath, const SecureBuffer& key);

result::Result<ByteBuffer> hexToBytes(std::string_view hex);
result::Result<SecureBuffer> hexToSecureBuffer(std::string_view hex);
result::Result<std::string> bytesToHex(std::span<const unsigned char> bytes);

result::Result<std::string> generateRandomEncryptionKeyHex();

}  // namespace crypto
