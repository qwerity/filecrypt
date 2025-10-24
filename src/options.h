#pragma once

#include "result.h"

#include <filesystem>
#include <string>
#include <variant>

namespace options {

enum class ProgramMode {
    Encrypt,
    Decrypt,
};

struct CommonOptions {
    std::filesystem::path inputPath;
    std::filesystem::path outputPath;
    std::string encryptionKeyHex;
};

struct EncryptOptions : CommonOptions {
    std::filesystem::path signingKeyPath;
};

struct DecryptOptions : CommonOptions {
    std::filesystem::path verifyKeyPath;
    std::string signatureHexInput;
};

using ProgramOptions = std::variant<EncryptOptions, DecryptOptions>;

result::Result<ProgramOptions> parseArguments(int argc, char** argv);

}  // namespace options
