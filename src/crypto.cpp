#include "crypto.h"
#include "file.h"

#include <cctype>
#include <array>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <system_error>
#include <span>
#include <string>
#include <vector>
#include <utility>

#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

namespace crypto {

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

template <typename T>
struct OpenSslFreeDeleter {
    void operator()(T* ptr) const noexcept {
        if (ptr != nullptr) {
            OPENSSL_free(ptr);
        }
    }
};

using OpenSslBytePtr = std::unique_ptr<unsigned char, OpenSslFreeDeleter<unsigned char>>;
using OpenSslCharPtr = std::unique_ptr<char, OpenSslFreeDeleter<char>>;

std::string currentOpenSslError() {
    std::array<char, 256> buffer{};
    const unsigned long code = ERR_get_error();
    if (code == 0U) {
        return "unknown OpenSSL error";
    }
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return {buffer.data()};
}

std::size_t resolveChunkSize(const std::filesystem::path& path) {
    constexpr std::size_t CHUNK_SIZE = 256 * 1024; // 256KiB
    constexpr std::size_t LARGE_CHUNK_SIZE = 4 * 1024 * 1024;  // 4 MiB chunks for large files
    constexpr std::uintmax_t LARGE_FILE_THRESHOLD = 512ULL * 1024ULL * 1024ULL;  // 1 GiB

    std::error_code ec;
    const auto fileSize = std::filesystem::file_size(path, ec);
    if (!ec && fileSize >= LARGE_FILE_THRESHOLD) {
        return LARGE_CHUNK_SIZE;
    }
    return std::min(fileSize, static_cast<std::size_t>(CHUNK_SIZE));
}

}  // namespace

result::Result<EvpKeyPtr> loadPrivateKey(const std::filesystem::path& path) {
    const BioPtr bio(BIO_new_file(path.string().c_str(), "r"), BIO_free);
    if (!bio) {
        return result::makeError("Failed to open private key: " + path.string() + " (" + currentOpenSslError() + ")");
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        return result::makeError("Failed to read private key: " + path.string() + " (" + currentOpenSslError() + ")");
    }
    return EvpKeyPtr(key);
}

result::Result<EvpKeyPtr> loadPublicKey(const std::filesystem::path& path) {
    const BioPtr bio(BIO_new_file(path.string().c_str(), "r"), BIO_free);
    if (!bio) {
        return result::makeError("Failed to open public key: " + path.string() + " (" + currentOpenSslError() + ")");
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        return result::makeError("Failed to read public key: " + path.string() + " (" + currentOpenSslError() + ")");
    }
    return EvpKeyPtr(key);
}

result::Result<ByteBuffer> signFile(const std::filesystem::path& path, EVP_PKEY* key) {
    const MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        return result::makeError("Failed to allocate digest context");
    }
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) {
        return result::makeError("EVP_DigestSignInit failed: " + currentOpenSslError());
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return result::makeError("Failed to open file for signing: " + path.string());
    }

    const auto bufferSize = resolveChunkSize(path);
    std::vector<char> buffer(bufferSize);
    std::span bufferSpan(buffer);
    const auto readContext = std::string("reading data for signing from ") + path.string();
    while (true) {
        const auto readResult = file::readSome(file, std::as_writable_bytes(bufferSpan), readContext);
        if (!readResult) {
            return result::makeError(readResult.error());
        }
        const auto bytesRead = readResult.value();
        if (bytesRead == 0) {
            break;
        }
        if (EVP_DigestSignUpdate(ctx.get(), buffer.data(), bytesRead) != 1) {
            return result::makeError("EVP_DigestSignUpdate failed: " + currentOpenSslError());
        }
    }

    size_t requiredSize = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &requiredSize) != 1) {
        return result::makeError("EVP_DigestSignFinal (size) failed: " + currentOpenSslError());
    }
    ByteBuffer signature(requiredSize);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &requiredSize) != 1) {
        return result::makeError("EVP_DigestSignFinal failed: " + currentOpenSslError());
    }
    signature.resize(requiredSize);
    return signature;
}

result::Result<void> verifyFileSignature(const std::filesystem::path& path, const ByteBuffer& signature, EVP_PKEY* key) {
    const MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        return result::makeError("Failed to allocate digest context");
    }
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) {
        return result::makeError("EVP_DigestVerifyInit failed: " + currentOpenSslError());
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return result::makeError("Failed to open file for verification: " + path.string());
    }

    const auto bufferSize = resolveChunkSize(path);
    std::vector<char> buffer(bufferSize);
    std::span<char> bufferSpan(buffer);
    const auto readContext = std::string("reading data for signature verification from ") + path.string();
    while (true) {
        const auto readResult = file::readSome(file, std::as_writable_bytes(bufferSpan), readContext);
        if (!readResult) {
            return result::makeError(readResult.error());
        }
        const auto bytesRead = readResult.value();
        if (bytesRead == 0) {
            break;
        }
        if (EVP_DigestVerifyUpdate(ctx.get(), buffer.data(), bytesRead) != 1) {
            return result::makeError("EVP_DigestVerifyUpdate failed: " + currentOpenSslError());
        }
    }

    const int result = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
    if (result == 1) {
        return {};
    }
    if (result == 0) {
        return result::makeError("Signature verification failed: plain text does not match the signature.");
    }
    return result::makeError("EVP_DigestVerifyFinal failed: " + currentOpenSslError());
}

result::Result<EncryptionResult> encryptFile(const std::filesystem::path& plainTextPath, const std::filesystem::path& cipherTextPath, const SecureBuffer& key) {
    if (key.size() != AES_256_KEY_SIZE) {
        return result::makeError("AES-256 key must be 32 bytes (64 hex characters)");
    }

    const auto plainPathStr = plainTextPath.string();
    const auto cipherPathStr = cipherTextPath.string();

    std::ifstream plainTextFile(plainTextPath, std::ios::binary);
    if (!plainTextFile) {
        return result::makeError("Failed to open plaintext file: " + plainPathStr);
    }
    std::ofstream cipherTextFile(cipherTextPath, std::ios::binary);
    if (!cipherTextFile) {
        return result::makeError("Failed to open ciphertext file: " + cipherPathStr);
    }

    EncryptionResult result;
    result.iv.resize(AES_256_GCM_IV_SIZE);
    if (RAND_bytes(result.iv.data(), static_cast<int>(result.iv.size())) != 1) {
        return result::makeError("RAND_bytes failed: " + currentOpenSslError());
    }

    const std::span<const unsigned char> ivSpan(result.iv);
    const auto ivWriteContext = std::string("writing IV to ") + cipherPathStr;
    if (const auto status = file::writeAll(cipherTextFile, std::as_bytes(ivSpan), ivWriteContext); !status) {
        return result::makeError(status.error());
    }

    const CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        return result::makeError("Failed to allocate cipher context");
    }
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return result::makeError("EVP_EncryptInit_ex failed: " + currentOpenSslError());
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(result.iv.size()), nullptr) != 1) {
        return result::makeError("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed: " + currentOpenSslError());
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), result.iv.data()) != 1) {
        return result::makeError("EVP_EncryptInit_ex (key/iv) failed: " + currentOpenSslError());
    }

    const auto bufferSize = resolveChunkSize(plainTextPath);
    std::vector<unsigned char> inBuffer(bufferSize);
    std::vector<unsigned char> outBuffer(bufferSize + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    std::span<unsigned char> inSpan(inBuffer);
    const auto readContext = std::string("reading plaintext for encryption from ") + plainPathStr;
    const auto writeContext = std::string("writing ciphertext chunk to ") + cipherPathStr;

    while (true) {
        const auto readResult = file::readSome(plainTextFile, std::as_writable_bytes(inSpan), readContext);
        if (!readResult) {
            return result::makeError(readResult.error());
        }
        const auto bytesRead = static_cast<int>(readResult.value());
        if (bytesRead == 0) {
            break;
        }
        if (EVP_EncryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), bytesRead) != 1) {
            return result::makeError("EVP_EncryptUpdate failed: " + currentOpenSslError());
        }
        if (outLen > 0) {
            std::span<const unsigned char> outSpan(outBuffer.data(), static_cast<std::size_t>(outLen));
            if (const auto status = file::writeAll(cipherTextFile, std::as_bytes(outSpan), writeContext); !status) {
                return result::makeError(status.error());
            }
        }
    }

    if (EVP_EncryptFinal_ex(ctx.get(), outBuffer.data(), &outLen) != 1) {
        return result::makeError("EVP_EncryptFinal_ex failed: " + currentOpenSslError());
    }
    if (outLen > 0) {
        std::span<const unsigned char> outSpan(outBuffer.data(), static_cast<std::size_t>(outLen));
        if (const auto status = file::writeAll(cipherTextFile, std::as_bytes(outSpan), writeContext); !status) {
            return result::makeError(status.error());
        }
    }

    result.tag.resize(AES_256_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(result.tag.size()), result.tag.data()) != 1) {
        return result::makeError("EVP_CIPHER_CTX_ctrl (GET_TAG) failed: " + currentOpenSslError());
    }

    const std::span<const unsigned char> tagSpan(result.tag);
    const auto tagWriteContext = std::string("writing authentication tag to ") + cipherPathStr;
    if (const auto status = file::writeAll(cipherTextFile, std::as_bytes(tagSpan), tagWriteContext); !status) {
        return result::makeError(status.error());
    }

    return result;
}

result::Result<void> decryptFile(const std::filesystem::path& cipherTextPath, const std::filesystem::path& plainTextPath, const SecureBuffer& key) {
    if (key.size() != AES_256_KEY_SIZE) {
        return result::makeError("AES-256 key must be 32 bytes (64 hex characters)");
    }

    const auto cipherPathStr = cipherTextPath.string();
    const auto plainPathStr = plainTextPath.string();

    std::ifstream cipherTextFile(cipherTextPath, std::ios::binary);
    if (!cipherTextFile) {
        return result::makeError("Failed to open ciphertext file: " + cipherPathStr);
    }
    std::ofstream plainTextFile(plainTextPath, std::ios::binary);
    if (!plainTextFile) {
        return result::makeError("Failed to open plaintext file: " + plainPathStr);
    }

    ByteBuffer iv(AES_256_GCM_IV_SIZE);
    const auto readIvContext = std::string("reading IV from ") + cipherPathStr;
    if (const auto status = file::readExact(cipherTextFile, std::as_writable_bytes(std::span(iv)), readIvContext); !status) {
        return status;
    }

    const auto seekTagContext = std::string("seeking to authentication tag in ") + cipherPathStr;
    if (const auto status = file::seek(cipherTextFile, -static_cast<std::streamoff>(AES_256_GCM_TAG_SIZE), std::ios::end, seekTagContext); !status) {
        return status;
    }
    ByteBuffer tag(AES_256_GCM_TAG_SIZE);
    const auto readTagContext = std::string("reading authentication tag from ") + cipherPathStr;
    if (const auto status = file::readExact(cipherTextFile, std::as_writable_bytes(std::span(tag)), readTagContext); !status) {
        return status;
    }

    const auto seekBodyContext = std::string("seeking to ciphertext body in ") + cipherPathStr;
    if (const auto status = file::seek(cipherTextFile, static_cast<std::streamoff>(AES_256_GCM_IV_SIZE), std::ios::beg, seekBodyContext); !status) {
        return status;
    }

    const CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        return result::makeError("Failed to allocate cipher context");
    }
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return result::makeError("EVP_DecryptInit_ex failed: " + currentOpenSslError());
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
        return result::makeError("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed: " + currentOpenSslError());
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        return result::makeError("EVP_DecryptInit_ex (key/iv) failed: " + currentOpenSslError());
    }

    const auto bufferSize = resolveChunkSize(cipherTextPath);
    std::vector<unsigned char> inBuffer(bufferSize);
    std::vector<unsigned char> outBuffer(bufferSize + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    if (const auto status = file::seek(cipherTextFile, 0, std::ios::end, std::string("seeking to end of ciphertext file ") + cipherPathStr); !status) {
        return status;
    }
    const std::streamoff totalSize = cipherTextFile.tellg();
    if (totalSize < 0) {
        auto message = std::string("Failed to determine ciphertext size for ") + cipherPathStr;
        std::cerr << message << '\n';
        return result::makeError(std::move(message));
    }
    if (const auto status = file::seek(cipherTextFile, static_cast<std::streamoff>(AES_256_GCM_IV_SIZE), std::ios::beg, seekBodyContext); !status) {
        return status;
    }
    const std::streamoff cipherTextOnlySize = totalSize - static_cast<std::streamoff>(AES_256_GCM_IV_SIZE) - static_cast<std::streamoff>(AES_256_GCM_TAG_SIZE);
    if (cipherTextOnlySize < 0) {
        return result::makeError("Invalid ciphertext file: file is too small for IV and tag.");
    }

    std::streamoff bytesRemaining = cipherTextOnlySize;
    const auto readCipherContext = std::string("reading ciphertext chunk from ") + cipherPathStr;
    const auto writePlainContext = std::string("writing plaintext chunk to ") + plainPathStr;
    while (bytesRemaining > 0) {
        const auto currentChunkSize = static_cast<std::size_t>(std::min<std::streamoff>(bytesRemaining, static_cast<std::streamoff>(inBuffer.size())));
        std::span chunkSpan(inBuffer.data(), currentChunkSize);
        if (const auto status = file::readExact(cipherTextFile, std::as_writable_bytes(chunkSpan), readCipherContext); !status) {
            return status;
        }
        if (EVP_DecryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), static_cast<int>(currentChunkSize)) != 1) {
            return result::makeError("EVP_DecryptUpdate failed: " + currentOpenSslError());
        }
        if (outLen > 0) {
            std::span<const unsigned char> outSpan(outBuffer.data(), static_cast<std::size_t>(outLen));
            if (const auto status = file::writeAll(plainTextFile, std::as_bytes(outSpan), writePlainContext); !status) {
                return status;
            }
        }
        bytesRemaining -= static_cast<std::streamoff>(currentChunkSize);
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        return result::makeError("EVP_CIPHER_CTX_ctrl (SET_TAG) failed: " + currentOpenSslError());
    }

    const int finalResult = EVP_DecryptFinal_ex(ctx.get(), outBuffer.data(), &outLen);
    if (finalResult != 1) {
        return result::makeError("Decryption failed: authentication tag mismatch");
    }
    if (outLen > 0) {
        std::span<const unsigned char> outSpan(outBuffer.data(), static_cast<std::size_t>(outLen));
        if (const auto status = file::writeAll(plainTextFile, std::as_bytes(outSpan), writePlainContext); !status) {
            return status;
        }
    }

    return {};
}

result::Result<ByteBuffer> hexToBytes(const std::string_view hex) {
    if (hex.empty()) {
        return {};
    }

    const std::string hexString(hex);
    long decodedLength = 0;
    const OpenSslBytePtr rawBuffer(OPENSSL_hexstr2buf(hexString.c_str(), &decodedLength));
    if (!rawBuffer) {
        return result::makeError("OPENSSL_hexstr2buf failed: " + currentOpenSslError());
    }
    if (decodedLength < 0) {
        return result::makeError("OPENSSL_hexstr2buf returned negative length");
    }
    ByteBuffer buffer(rawBuffer.get(), rawBuffer.get() + static_cast<std::size_t>(decodedLength));
    return buffer;
}

result::Result<SecureBuffer> hexToSecureBuffer(const std::string_view hex) {
    auto bytes = hexToBytes(hex);
    if (!bytes) {
        return result::makeError(bytes.error());
    }
    return SecureBuffer(std::move(bytes.value()));
}

result::Result<std::string> bytesToHex(const std::span<const unsigned char> bytes) {
    if (bytes.empty()) {
        return {};
    }

    const OpenSslCharPtr hexBuffer(OPENSSL_buf2hexstr(bytes.data(), static_cast<long>(bytes.size())));
    if (!hexBuffer) {
        return result::makeError("OPENSSL_buf2hexstr failed: " + currentOpenSslError());
    }

    std::string hexString(hexBuffer.get());

    hexString.erase(std::ranges::remove(hexString, ':').begin(), hexString.end());
    std::ranges::transform(hexString, hexString.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    return hexString;
}

result::Result<std::string> generateRandomEncryptionKeyHex() {
    SecureBuffer encKey(AES_256_KEY_SIZE);

    if (RAND_bytes(encKey.data(), static_cast<int>(encKey.size())) != 1) {
        return result::makeError("RAND_bytes failed: " + currentOpenSslError());
    }

    const auto hexEnckey = bytesToHex(encKey.span());
    if (!hexEnckey) {
        return result::makeError(hexEnckey.error());
    }
    return hexEnckey;
}

}  // namespace crypto
