#include "crypto.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <random>
#include <ranges>
#include <vector>

class CryptoTest : public ::testing::Test {
protected:
    const std::filesystem::path privateKeyPath = "./tests/data/ec_private.pem";
    const std::filesystem::path publicKeyPath = "./tests/data/ec_public.pem";
    const std::filesystem::path plainTextPath = "./tests/data/plain.txt";
    const std::filesystem::path cipherTextPath = "test_file.enc";
    const std::filesystem::path decryptedTextPath = "test_file.dec";
};

TEST_F(CryptoTest, KeyLoading) {
    const auto privateKey = crypto::loadPrivateKey(privateKeyPath);
    ASSERT_TRUE(privateKey.has_value());

    const auto publicKey = crypto::loadPublicKey(publicKeyPath);
    ASSERT_TRUE(publicKey.has_value());
}

TEST_F(CryptoTest, SignAndVerify) {
    const auto privateKey = crypto::loadPrivateKey(privateKeyPath).value();
    const auto publicKey = crypto::loadPublicKey(publicKeyPath).value();

    const auto signature = crypto::signFile(plainTextPath, privateKey.get());
    ASSERT_TRUE(signature.has_value());

    const auto verification = crypto::verifyFileSignature(plainTextPath, signature.value(), publicKey.get());
    EXPECT_TRUE(verification.has_value());
}

TEST_F(CryptoTest, EncryptAndDecrypt) {
    const auto key = crypto::hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();

    const auto encResult = crypto::encryptFile(plainTextPath, cipherTextPath, key);
    ASSERT_TRUE(encResult.has_value());

    const auto decResult = crypto::decryptFile(cipherTextPath, decryptedTextPath, key);
    ASSERT_TRUE(decResult.has_value());

    // Compare the original and decrypted files
    std::ifstream original_file(plainTextPath);
    std::ifstream decrypted_file(decryptedTextPath);
    const std::string original_content((std::istreambuf_iterator<char>(original_file)), std::istreambuf_iterator<char>());
    const std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_file)), std::istreambuf_iterator<char>());
    EXPECT_EQ(original_content, decrypted_content);

    std::remove(cipherTextPath.c_str());
    std::remove(decryptedTextPath.c_str());
}

TEST_F(CryptoTest, EmptyFile) {
    std::ofstream empty_file("empty_file.txt");
    empty_file.close();

    const auto key = crypto::hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();

    const auto encResult = crypto::encryptFile("empty_file.txt", "empty_file.enc", key);
    ASSERT_TRUE(encResult.has_value());

    const auto decResult = crypto::decryptFile("empty_file.enc", "empty_file.dec", key);
    ASSERT_TRUE(decResult.has_value());

    std::ifstream decrypted_file("empty_file.dec");
    const std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_file)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(decrypted_content.empty());

    std::remove("empty_file.txt");
    std::remove("empty_file.enc");
    std::remove("empty_file.dec");
}

TEST_F(CryptoTest, IncorrectKey) {
    const auto key = crypto::hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();
    const auto wrong_key = crypto::hexToBytes("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").value();

    const auto encResult = crypto::encryptFile(plainTextPath, cipherTextPath, key);
    ASSERT_TRUE(encResult.has_value());

    const auto decResult = crypto::decryptFile(cipherTextPath, decryptedTextPath, wrong_key);
    EXPECT_FALSE(decResult.has_value());

    std::remove(cipherTextPath.c_str());
    std::remove(decryptedTextPath.c_str());
}

TEST_F(CryptoTest, CorruptedSignature) {
    const auto privateKey = crypto::loadPrivateKey(privateKeyPath).value();
    const auto publicKey = crypto::loadPublicKey(publicKeyPath).value();

    auto signature = crypto::signFile(plainTextPath, privateKey.get());
    ASSERT_TRUE(signature.has_value());

    // Modify the signature
    signature.value()[0]++;

    const auto verification = crypto::verifyFileSignature(plainTextPath, signature.value(), publicKey.get());
    EXPECT_FALSE(verification.has_value());
}

TEST_F(CryptoTest, CorruptedCiphertext) {
    const auto key = crypto::hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();

    const auto encResult = crypto::encryptFile(plainTextPath, cipherTextPath, key);
    ASSERT_TRUE(encResult.has_value());

    // Corrupt the ciphertext
    std::fstream cipher_file(cipherTextPath, std::ios::in | std::ios::out | std::ios::binary);
    cipher_file.seekp(12); // Skip IV
    cipher_file.put('X');
    cipher_file.close();

    const auto decResult = crypto::decryptFile(cipherTextPath, decryptedTextPath, key);
    EXPECT_FALSE(decResult.has_value());

    std::remove(cipherTextPath.c_str());
    std::remove(decryptedTextPath.c_str());
}

TEST_F(CryptoTest, BinaryFileRoundTrip) {
    const std::filesystem::path binaryPath = "binary_blob.bin";
    const std::filesystem::path cipherPath = "binary_blob.enc";
    const std::filesystem::path restoredPath = "binary_blob.dec";

    {
        std::ofstream binary(binaryPath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(binary.is_open());
        for (int i = 0; i < 4096; ++i) {
            const auto byte = static_cast<unsigned char>(i % 256);
            binary.write(reinterpret_cast<const char*>(&byte), sizeof(byte));
        }
    }

    const auto key = crypto::hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();
    auto encResult = crypto::encryptFile(binaryPath, cipherPath, key);
    ASSERT_TRUE(encResult.has_value());
    auto decResult = crypto::decryptFile(cipherPath, restoredPath, key);
    ASSERT_TRUE(decResult.has_value());

    std::ifstream original(binaryPath, std::ios::binary);
    std::ifstream restored(restoredPath, std::ios::binary);
    std::vector<char> originalData((std::istreambuf_iterator<char>(original)), std::istreambuf_iterator<char>());
    std::vector<char> restoredData((std::istreambuf_iterator<char>(restored)), std::istreambuf_iterator<char>());
    EXPECT_EQ(originalData, restoredData);

    std::remove(binaryPath.c_str());
    std::remove(cipherPath.c_str());
    std::remove(restoredPath.c_str());
}

TEST_F(CryptoTest, HexToBytesAndBack) {
    const auto bytes = crypto::hexToBytes("deadbeef");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(bytes.value(), std::vector<unsigned char>({0xde, 0xad, 0xbe, 0xef}));

    const auto hex = crypto::bytesToHex(bytes.value());
    ASSERT_TRUE(hex.has_value());
    EXPECT_EQ(hex.value(), "deadbeef");
}

TEST_F(CryptoTest, HexToBytesRejectsInvalidChars) {
    const auto bytes = crypto::hexToBytes("deadbeefg");
    EXPECT_FALSE(bytes.has_value());
}

TEST_F(CryptoTest, HexToBytesHandlesEmptyString) {
    const auto bytes = crypto::hexToBytes("");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_TRUE(bytes.value().empty());
}

TEST_F(CryptoTest, GenerateRandomEncryptionKeyHexProducesValidHex) {
    const auto keyHex = crypto::generateRandomEncryptionKeyHex();
    ASSERT_TRUE(keyHex.has_value());
    EXPECT_EQ(keyHex->size(), 64U);
    EXPECT_TRUE(std::ranges::all_of(*keyHex, [](const char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }));

    const auto keyBytes = crypto::hexToBytes(keyHex.value());
    ASSERT_TRUE(keyBytes.has_value());
    EXPECT_EQ(keyBytes->size(), 32U);
}

TEST_F(CryptoTest, GenerateRandomEncryptionKeyHexProducesDifferentValues) {
    const auto first = crypto::generateRandomEncryptionKeyHex();
    const auto second = crypto::generateRandomEncryptionKeyHex();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first.value(), second.value());
}
