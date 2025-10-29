#include "crypto.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <system_error>
#include <string>
#include <vector>

#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

namespace crypto {

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string currentOpenSslError() {
    std::array<char, 256> buffer{};
    const unsigned long code = ERR_get_error();
    if (code == 0U) {
        return "unknown OpenSSL error";
    }
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return {buffer.data()};
}

constexpr std::size_t CHUNK_SIZE = 4096;
constexpr std::size_t LARGE_CHUNK_SIZE = 1024 * 1024;  // 1 MiB chunks for large files
constexpr std::uintmax_t LARGE_FILE_THRESHOLD = 1024ULL * 1024ULL * 1024ULL;  // 1 GiB
constexpr std::size_t AES_256_KEY_SIZE = 32;
constexpr std::size_t AES_256_GCM_IV_SIZE = 12;
constexpr std::size_t AES_256_GCM_TAG_SIZE = 16;

std::size_t resolveChunkSize(const std::filesystem::path& path) {
    std::error_code ec;
    const auto fileSize = std::filesystem::file_size(path, ec);
    if (!ec && fileSize >= LARGE_FILE_THRESHOLD) {
        return LARGE_CHUNK_SIZE;
    }
    return CHUNK_SIZE;
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
    while (file) {
        file.read(buffer.data(), buffer.size());
        const auto bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (EVP_DigestSignUpdate(ctx.get(), buffer.data(), bytesRead) != 1) {
                return result::makeError("EVP_DigestSignUpdate failed: " + currentOpenSslError());
            }
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
    while (file) {
        file.read(buffer.data(), buffer.size());
        const auto bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (EVP_DigestVerifyUpdate(ctx.get(), buffer.data(), bytesRead) != 1) {
                return result::makeError("EVP_DigestVerifyUpdate failed: " + currentOpenSslError());
            }
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

result::Result<EncryptionResult> encryptFile(const std::filesystem::path& plainTextPath, const std::filesystem::path& cipherTextPath, const ByteBuffer& key) {
    if (key.size() != AES_256_KEY_SIZE) {
        return result::makeError("AES-256 key must be 32 bytes (64 hex characters)");
    }

    std::ifstream plainTextFile(plainTextPath, std::ios::binary);
    if (!plainTextFile) {
        return result::makeError("Failed to open plaintext file: " + plainTextPath.string());
    }
    std::ofstream cipherTextFile(cipherTextPath, std::ios::binary);
    if (!cipherTextFile) {
        return result::makeError("Failed to open ciphertext file: " + cipherTextPath.string());
    }

    const auto bufferSize = resolveChunkSize(plainTextPath);
    EncryptionResult result;
    result.iv.resize(AES_256_GCM_IV_SIZE);
    if (RAND_bytes(result.iv.data(), static_cast<int>(result.iv.size())) != 1) {
        return result::makeError("RAND_bytes failed: " + currentOpenSslError());
    }

    cipherTextFile.write(reinterpret_cast<char*>(result.iv.data()),  static_cast<int>(result.iv.size()));

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

    std::vector<unsigned char> inBuffer(bufferSize);
    std::vector<unsigned char> outBuffer(bufferSize + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;

    while (plainTextFile) {
        plainTextFile.read(reinterpret_cast<char*>(inBuffer.data()), inBuffer.size());
        const auto bytesRead = static_cast<int>(plainTextFile.gcount());
        if (bytesRead > 0) {
            if (EVP_EncryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), bytesRead) != 1) {
                return result::makeError("EVP_EncryptUpdate failed: " + currentOpenSslError());
            }
            cipherTextFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
        }
    }

    if (EVP_EncryptFinal_ex(ctx.get(), outBuffer.data(), &outLen) != 1) {
        return result::makeError("EVP_EncryptFinal_ex failed: " + currentOpenSslError());
    }
    cipherTextFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    result.tag.resize(AES_256_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(result.tag.size()), result.tag.data()) != 1) {
        return result::makeError("EVP_CIPHER_CTX_ctrl (GET_TAG) failed: " + currentOpenSslError());
    }

    cipherTextFile.write(reinterpret_cast<char*>(result.tag.data()), result.tag.size());

    return result;
}

result::Result<void> decryptFile(const std::filesystem::path& cipherTextPath, const std::filesystem::path& plainTextPath, const ByteBuffer& key) {
    if (key.size() != AES_256_KEY_SIZE) {
        return result::makeError("AES-256 key must be 32 bytes (64 hex characters)");
    }

    std::ifstream cipherTextFile(cipherTextPath, std::ios::binary);
    if (!cipherTextFile) {
        return result::makeError("Failed to open ciphertext file: " + cipherTextPath.string());
    }
    std::ofstream plainTextFile(plainTextPath, std::ios::binary);
    if (!plainTextFile) {
        return result::makeError("Failed to open plaintext file: " + plainTextPath.string());
    }

    ByteBuffer iv(AES_256_GCM_IV_SIZE);
    cipherTextFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

    cipherTextFile.seekg(-static_cast<long>(AES_256_GCM_TAG_SIZE), std::ios::end);
    ByteBuffer tag(AES_256_GCM_TAG_SIZE);
    cipherTextFile.read(reinterpret_cast<char*>(tag.data()), tag.size());
    cipherTextFile.seekg(AES_256_GCM_IV_SIZE, std::ios::beg);

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

    cipherTextFile.seekg(0, std::ios::end);
    const std::streamoff totalSize = cipherTextFile.tellg();
    cipherTextFile.seekg(AES_256_GCM_IV_SIZE, std::ios::beg);
    const std::streamoff cipherTextOnlySize = totalSize - AES_256_GCM_IV_SIZE - AES_256_GCM_TAG_SIZE;

    std::streamoff bytesToRead = cipherTextOnlySize;
    const auto chunkSize = static_cast<std::streamsize>(bufferSize);
    while (bytesToRead > 0) {
        std::streamsize currentChunkSize = chunkSize;
        if (bytesToRead < currentChunkSize) {
            currentChunkSize = static_cast<std::streamsize>(bytesToRead);
        }
        cipherTextFile.read(reinterpret_cast<char*>(inBuffer.data()), currentChunkSize);
        if (EVP_DecryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), currentChunkSize) != 1) {
            return result::makeError("EVP_DecryptUpdate failed: " + currentOpenSslError());
        }
        plainTextFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
        bytesToRead -= currentChunkSize;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        return result::makeError("EVP_CIPHER_CTX_ctrl (SET_TAG) failed: " + currentOpenSslError());
    }

    const int finalResult = EVP_DecryptFinal_ex(ctx.get(), outBuffer.data(), &outLen);
    if (finalResult != 1) {
        return result::makeError("Decryption failed: authentication tag mismatch");
    }
    plainTextFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    return {};
}

result::Result<ByteBuffer> hexToBytes(const std::string_view hex) {
    if (hex.empty()) {
        return {};
    }

    const std::string hexString(hex);
    long decodedLength = 0;
    unsigned char* rawBuffer = OPENSSL_hexstr2buf(hexString.c_str(), &decodedLength);
    if (rawBuffer == nullptr) {
        return result::makeError("OPENSSL_hexstr2buf failed: " + currentOpenSslError());
    }
    if (decodedLength < 0) {
        OPENSSL_free(rawBuffer);
        return result::makeError("OPENSSL_hexstr2buf returned negative length");
    }
    ByteBuffer buffer(rawBuffer, rawBuffer + static_cast<std::size_t>(decodedLength));
    OPENSSL_free(rawBuffer);
    return buffer;
}

result::Result<std::string> bytesToHex(const ByteBuffer& bytes) {
    if (bytes.empty()) {
        return {};
    }

    char* hexBuffer = OPENSSL_buf2hexstr(bytes.data(), static_cast<long>(bytes.size()));
    if (hexBuffer == nullptr) {
        return result::makeError("OPENSSL_buf2hexstr failed: " + currentOpenSslError());
    }

    std::string hexString(hexBuffer);
    OPENSSL_free(hexBuffer);

    hexString.erase(std::ranges::remove(hexString, ':').begin(), hexString.end());
    std::ranges::transform(hexString, hexString.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    return hexString;
}

result::Result<std::string> generateRandomEncryptionKeyHex() {
    ByteBuffer encKey(AES_256_KEY_SIZE);

    if (RAND_bytes(encKey.data(), static_cast<int>(encKey.size())) != 1) {
        return result::makeError("RAND_bytes failed: " + currentOpenSslError());
    }

    const auto hexEnckey = bytesToHex(encKey);
    if (!hexEnckey) {
        return result::makeError(hexEnckey.error());
    }
    return hexEnckey;
}

}  // namespace crypto
