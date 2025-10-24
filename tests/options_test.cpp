#include "options.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

namespace {

class TempFile {
public:
    explicit TempFile(std::string name) : path(std::move(name)) {
        std::ofstream file(path);
        file << "x";
    }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    [[nodiscard]] const char* c_str() const { return path.c_str(); }
    [[nodiscard]] const std::filesystem::path& get() const { return path; }

private:
    std::filesystem::path path;
};

}  // namespace

TEST(OptionsTest, EncryptMode) {
    TempFile input("opt_input_enc.txt");
    TempFile sign("opt_sign.pem");
    const char* argv[] = {"filecrypt", "encrypt", "--in", input.c_str(), "--out", "output.txt", "--enc-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "--sign-key", sign.c_str()};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    ASSERT_TRUE(optionsVariant.has_value());
    const auto* encryptOptions = std::get_if<options::EncryptOptions>(&optionsVariant.value());
    ASSERT_NE(encryptOptions, nullptr);
    EXPECT_EQ(encryptOptions->inputPath, input.get());
    EXPECT_EQ(encryptOptions->outputPath, std::filesystem::path("output.txt"));
}

TEST(OptionsTest, DecryptMode) {
    TempFile input("opt_input_dec.txt");
    TempFile verify("opt_verify.pem");
    const char* argv[] = {"filecrypt", "decrypt", "--in", input.c_str(), "--out", "output.txt", "--enc-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "--verify-key", verify.c_str(), "--signature", "abcdef"};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    ASSERT_TRUE(optionsVariant.has_value());
    const auto* decryptOptions = std::get_if<options::DecryptOptions>(&optionsVariant.value());
    ASSERT_NE(decryptOptions, nullptr);
    EXPECT_EQ(decryptOptions->signatureHexInput, "abcdef");
}

TEST(OptionsTest, MissingMode) {
    const char* argv[] = {"filecrypt"};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    EXPECT_FALSE(optionsVariant.has_value());
}

TEST(OptionsTest, InvalidArgument) {
    const char* argv[] = {"filecrypt", "encrypt", "--invalid-arg"};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    EXPECT_FALSE(optionsVariant.has_value());
}

TEST(OptionsTest, MissingValue) {
    const char* argv[] = {"filecrypt", "encrypt", "--in"};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    EXPECT_FALSE(optionsVariant.has_value());
}

TEST(OptionsTest, UnknownArgument) {
    const char* argv[] = {"filecrypt", "encrypt", "--unknown"};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    EXPECT_FALSE(optionsVariant.has_value());
}

TEST(OptionsTest, DecryptMissingSignature) {
    const char* argv[] = {"filecrypt", "decrypt", "--in", "input.txt", "--enc-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "--verify-key", "public.pem"};
    constexpr int argc = sizeof(argv) / sizeof(char*);

    const auto optionsVariant = options::parseArguments(argc, const_cast<char**>(argv));
    EXPECT_FALSE(optionsVariant.has_value());
}
