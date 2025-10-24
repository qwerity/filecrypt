#include "functions.h"
#include "options.h"
#include "crypto.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <fstream>
#include <random>
#include <vector>

class FunctionalTest : public ::testing::Test {
protected:
    const std::filesystem::path privateKeyPath = "./tests/data/ec_private.pem";
    const std::filesystem::path publicKeyPath = "./tests/data/ec_public.pem";
    const std::filesystem::path plainTextPath = "./tests/data/plain.txt";
    const std::filesystem::path cipherTextPath = "test_file.enc";
    const std::filesystem::path decryptedTextPath = "test_file.dec";
};

TEST_F(FunctionalTest, EncryptDecrypt) {
    options::EncryptOptions encOptions;
    encOptions.inputPath = plainTextPath;
    encOptions.outputPath = cipherTextPath;
    encOptions.encryptionKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    encOptions.signingKeyPath = privateKeyPath;

    const auto encStatus = runEncrypt(encOptions);
    ASSERT_TRUE(encStatus.has_value());

    const auto privateKey = crypto::loadPrivateKey(privateKeyPath).value();
    const auto signature = crypto::signFile(plainTextPath, privateKey.get());
    ASSERT_TRUE(signature.has_value());
    const auto signatureHex = crypto::bytesToHex(signature.value());
    ASSERT_TRUE(signatureHex.has_value());

    options::DecryptOptions decOptions;
    decOptions.inputPath = cipherTextPath;
    decOptions.outputPath = decryptedTextPath;
    decOptions.encryptionKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    decOptions.verifyKeyPath = publicKeyPath;
    decOptions.signatureHexInput = signatureHex.value();

    const auto decStatus = runDecrypt(decOptions);
    ASSERT_TRUE(decStatus.has_value());

    std::ifstream original_file(plainTextPath);
    std::ifstream decrypted_file(decryptedTextPath);
    const std::string original_content((std::istreambuf_iterator<char>(original_file)), std::istreambuf_iterator<char>());
    const std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_file)), std::istreambuf_iterator<char>());
    EXPECT_EQ(original_content, decrypted_content);

    std::remove(cipherTextPath.c_str());
    std::remove(decryptedTextPath.c_str());
}

TEST_F(FunctionalTest, LargeOneGigabyteFileSignEncryptDecryptVerify) {
    const std::filesystem::path largeFilePath = "large_file_1gb.bin";
    const std::filesystem::path largeCipherPath = "large_file_1gb.enc";
    const std::filesystem::path largeDecryptedPath = "large_file_1gb.dec";
    constexpr std::uintmax_t largeFileSize = 1024ULL * 1024ULL * 1024ULL;  // 1 GiB

    {
        std::ofstream largeFile(largeFilePath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(largeFile.is_open());
        constexpr std::size_t chunkSize = 1024 * 1024;
        std::vector<char> buffer(chunkSize);
        std::mt19937 rng(123456u);
        std::uniform_int_distribution printable(32, 126);  // printable ASCII range

        const auto fillBuffer = [&](const std::size_t length) {
            for (std::size_t i = 0; i < length; ++i) {
                buffer[i] = static_cast<char>(printable(rng));
            }
        };

        std::uintmax_t remaining = largeFileSize;
        while (remaining > 0) {
            const auto currentChunk = static_cast<std::size_t>(std::min<std::uintmax_t>(remaining, chunkSize));
            fillBuffer(currentChunk);
            largeFile.write(buffer.data(), static_cast<std::streamsize>(currentChunk));
            remaining -= currentChunk;
        }
    }
    ASSERT_EQ(std::filesystem::file_size(largeFilePath), largeFileSize);

    const auto key = crypto::hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();
    const auto privateKey = crypto::loadPrivateKey(privateKeyPath).value();
    const auto publicKey = crypto::loadPublicKey(publicKeyPath).value();

    const auto signature = crypto::signFile(largeFilePath, privateKey.get());
    ASSERT_TRUE(signature.has_value());

    const auto encResult = crypto::encryptFile(largeFilePath, largeCipherPath, key);
    ASSERT_TRUE(encResult.has_value());

    const auto decResult = crypto::decryptFile(largeCipherPath, largeDecryptedPath, key);
    ASSERT_TRUE(decResult.has_value());

    const auto verification = crypto::verifyFileSignature(largeDecryptedPath, signature.value(), publicKey.get());
    EXPECT_TRUE(verification.has_value());
    ASSERT_EQ(std::filesystem::file_size(largeDecryptedPath), largeFileSize);

    std::remove(largeFilePath.c_str());
    std::remove(largeCipherPath.c_str());
    std::remove(largeDecryptedPath.c_str());
}
