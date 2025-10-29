#pragma once

#include "result.h"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace crypto {

using ByteBuffer = std::vector<unsigned char>;

struct EvpKeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        if (key != nullptr) {
            EVP_PKEY_free(key);
        }
    }
};

using EvpKeyPtr = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

result::Result<EvpKeyPtr> loadPrivateKey(const std::filesystem::path& path);
result::Result<EvpKeyPtr> loadPublicKey(const std::filesystem::path& path);

result::Result<ByteBuffer> signFile(const std::filesystem::path& path, EVP_PKEY* key);
result::Result<void> verifyFileSignature(const std::filesystem::path& path, const ByteBuffer& signature, EVP_PKEY* key);

struct EncryptionResult {
    ByteBuffer iv{};
    ByteBuffer tag{};
};

result::Result<EncryptionResult> encryptFile(const std::filesystem::path& plainTextPath, const std::filesystem::path& cipherTextPath, const ByteBuffer& key);
result::Result<void> decryptFile(const std::filesystem::path& cipherTextPath, const std::filesystem::path& plainTextPath, const ByteBuffer& key);

result::Result<ByteBuffer> hexToBytes(std::string_view hex);
result::Result<std::string> bytesToHex(const ByteBuffer& bytes);

result::Result<std::string> generateRandomEncryptionKeyHex();

}  // namespace crypto
