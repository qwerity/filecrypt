#include "options.h"
#include "crypto.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace options {

namespace {

std::string usageText() {
    return
        "Usage:\n"
        "  filecrypt encrypt --in <plain.txt> [--out <cipher.bin>] [--enc-key <64 hex>]\\\n"
        "                    --sign-key <private.pem>\n"
        "    --in         plaintext file path to encrypt\n"
        "    --out        ciphertext file path (defaults to <in>.enc)\n"
        "    --enc-key    32-byte AES256 key (64 hex). Auto-generated if omitted.\n"
        "    --sign-key   PEM private key file path used to sign the plaintext\n"
        "\n"
        "  filecrypt decrypt --in <cipher.bin> [--out <plain.txt>] --enc-key <64 hex>\\\n"
        "                    --verify-key <public.pem> --signature <hex>\n"
        "    --in         ciphertext file path to decrypt\n"
        "    --out        plaintext file path (defaults to <in>.txt)\n"
        "    --enc-key    same AES256 key used at encrypt time\n"
        "    --verify-key PEM public key file path that matches --sign-key\\\n"
        "                 to check the plaintext integrity\n"
        "    --signature  plain text signature\n"
        "\n";
}

}  // namespace

result::Result<EncryptOptions> parseEncrypt(int argc, char** argv) {
    EncryptOptions opts;
    bool inputSet = false;
    bool outputSet = false;
    bool keySet = false;
    bool signSet = false;

    auto readNextValue = [&](int& index, const char* optionName) -> result::Result<std::string> {
        if (index + 1 >= argc) {
            return result::makeError(std::string("Missing value for ") + optionName);
        }
        return std::string(argv[++index]);
    };

    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--in") {
            auto value = readNextValue(i, "--in");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.inputPath = *value;
            inputSet = true;
        } else if (arg == "--out") {
            auto value = readNextValue(i, "--out");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.outputPath = *value;
            outputSet = true;
        } else if (arg == "--enc-key") {
            auto value = readNextValue(i, "--enc-key");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.encryptionKeyHex = std::move(*value);
            keySet = true;
        } else if (arg == "--sign-key") {
            auto value = readNextValue(i, "--sign-key");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.signingKeyPath = *value;
            signSet = true;
        } else if (arg == "--help") {
            std::cout << usageText();
            std::exit(0);
        } else {
            return result::makeError("Unknown argument: " + std::string(arg) + "\n" + usageText());
        }
    }

    if (!inputSet) {
        return result::makeError("Argument --in is required.\n" + usageText());
    }
    if (!signSet) {
        return result::makeError("--sign-key is required for encryption");
    }
    if (!keySet) {
        const auto encKeyHex = crypto::generateRandomEncryptionKeyHex();
        if (!encKeyHex) {
            return result::makeError(encKeyHex.error());
        }
        opts.encryptionKeyHex = *encKeyHex;
        std::cerr << "Warning: --enc-key not specified. Generated random key: " << opts.encryptionKeyHex << "\n";
    }
    if (!outputSet) {
        opts.outputPath = opts.inputPath;
        opts.outputPath += ".enc";
        std::cerr << "Warning: --out not specified. Defaulting to " << opts.outputPath << "\n";
    }

    if (!std::filesystem::exists(opts.inputPath)) {
        return result::makeError("Input file does not exist: " + opts.inputPath.string());
    }
    if (!std::filesystem::exists(opts.signingKeyPath)) {
        return result::makeError("Signing key file does not exist: " + opts.signingKeyPath.string());
    }

    return opts;
}

result::Result<DecryptOptions> parseDecrypt(int argc, char** argv) {
    DecryptOptions opts;
    bool inputSet = false;
    bool outputSet = false;
    bool keySet = false;
    bool verifySet = false;
    bool signatureSet = false;

    auto readNextValue = [&](int& index, const char* optionName) -> result::Result<std::string> {
        if (index + 1 >= argc) {
            return result::makeError(std::string("Missing value for ") + optionName);
        }
        return std::string(argv[++index]);
    };

    for (int i = 2; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--in") {
            auto value = readNextValue(i, "--in");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.inputPath = *value;
            inputSet = true;
        } else if (arg == "--out") {
            auto value = readNextValue(i, "--out");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.outputPath = *value;
            outputSet = true;
        } else if (arg == "--enc-key") {
            auto value = readNextValue(i, "--enc-key");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.encryptionKeyHex = std::move(*value);
            keySet = true;
        } else if (arg == "--verify-key") {
            auto value = readNextValue(i, "--verify-key");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.verifyKeyPath = *value;
            verifySet = true;
        } else if (arg == "--signature") {
            auto value = readNextValue(i, "--signature");
            if (!value) {
                return result::makeError(value.error());
            }
            opts.signatureHexInput = std::move(*value);
            signatureSet = true;
        } else if (arg == "--help") {
            std::cout << usageText();
            std::exit(0);
        } else {
            return result::makeError("Unknown argument: " + std::string(arg) + "\n" + usageText());
        }
    }

    if (!inputSet) {
        return result::makeError("Argument --in is required.\n" + usageText());
    }
    if (!keySet) {
        return result::makeError("Argument --enc-key is required.\n" + usageText());
    }
    if (!verifySet) {
        return result::makeError("--verify-key is required for decryption");
    }
    if (!signatureSet) {
        return result::makeError("--signature is required for decryption (pass the value printed during encrypt)");
    }
    if (!outputSet) {
        opts.outputPath = opts.inputPath;
        opts.outputPath += ".txt";
        std::cerr << "Warning: --out not specified. Defaulting to " << opts.outputPath << "\n";
    }

    if (!std::filesystem::exists(opts.inputPath)) {
        return result::makeError("Input file does not exist: " + opts.inputPath.string());
    }
    if (!std::filesystem::exists(opts.verifyKeyPath)) {
        return result::makeError("Verification key file does not exist: " + opts.verifyKeyPath.string());
    }

    return opts;
}

result::Result<ProgramOptions> parseArguments(int argc, char** argv) {
    if (argc < 2) {
        return result::makeError("Missing mode. Use 'encrypt' or 'decrypt'.\n" + usageText());
    }

    const std::string modeArg = argv[1];
    if (modeArg == "--help") {
        std::cout << usageText();
        std::exit(0);
    }

    if (modeArg == "encrypt") {
        auto opts = parseEncrypt(argc, argv);
        if (!opts) {
            return result::makeError(opts.error());
        }
        return ProgramOptions{std::in_place_type<EncryptOptions>, std::move(*opts)};
    }
    if (modeArg == "decrypt") {
        auto opts = parseDecrypt(argc, argv);
        if (!opts) {
            return result::makeError(opts.error());
        }
        return ProgramOptions{std::in_place_type<DecryptOptions>, std::move(*opts)};
    }

    return result::makeError("Unknown mode: " + modeArg + ".  Use 'encrypt' or 'decrypt'.\n" + usageText());
}

}  // namespace options
