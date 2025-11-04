#include "functions.h"
#include "crypto.h"

#include <iostream>

result::Status runEncrypt(const options::EncryptOptions& options) {
    auto encKeyResult = crypto::hexToSecureBuffer(options.encryptionKeyHex);
    if (!encKeyResult) {
        return result::makeError(encKeyResult.error());
    }

    const auto signingKeyResult = crypto::loadPrivateKey(options.signingKeyPath);
    if (!signingKeyResult) {
        return result::makeError(signingKeyResult.error());
    }

    const auto encryptedResult = crypto::encryptFile(options.inputPath, options.outputPath, encKeyResult.value());
    if (!encryptedResult) {
        std::error_code ec{};
        std::filesystem::remove(options.outputPath, ec);
        return result::makeError(encryptedResult.error());
    }

    const auto ivHex = crypto::bytesToHex(encryptedResult->iv);
    if (!ivHex) {
        return result::makeError(ivHex.error());
    }

    const auto tagHex = crypto::bytesToHex(encryptedResult->tag);
    if (!tagHex) {
        return result::makeError(tagHex.error());
    }

    const auto signatureResult = crypto::signFile(options.inputPath, signingKeyResult->get());
    if (!signatureResult) {
        return result::makeError(signatureResult.error());
    }

    const auto signatureHex = crypto::bytesToHex(signatureResult.value());
    if (!signatureHex) {
        return result::makeError(signatureHex.error());
    }

    std::cout << "Encryption complete.\n";
    if (options.verbose)
    {
        std::cout << "Key (hex): " << options.encryptionKeyHex << "\n";
        std::cout << "IV (hex): " << *ivHex << "\n";
        std::cout << "Tag (hex): " << *tagHex << "\n";
    }
    std::cout << "Signature (hex): " << *signatureHex << "\n";
    std::cout << "Encrypted to " << options.outputPath.string() << "\n";

    return {};
}

result::Status runDecrypt(const options::DecryptOptions& options) {
    auto encKeyResult = crypto::hexToSecureBuffer(options.encryptionKeyHex);
    if (!encKeyResult) {
        return result::makeError(encKeyResult.error());
    }

    const auto signatureBytes = crypto::hexToBytes(options.signatureHexInput);
    if (!signatureBytes) {
        return result::makeError(signatureBytes.error());
    }

    const auto verificationKeyResult = crypto::loadPublicKey(options.verifyKeyPath);
    if (!verificationKeyResult) {
        return result::makeError(verificationKeyResult.error());
    }

    if (const auto status = crypto::decryptFile(options.inputPath, options.outputPath, encKeyResult.value()); !status) {
        std::error_code ec{};
        std::filesystem::remove(options.outputPath, ec);
        return status;
    }

    if (const auto status = crypto::verifyFileSignature(options.outputPath, *signatureBytes, verificationKeyResult->get()); !status) {
        return status;
    }

    std::cout << "Decryption complete and signature verified successfully.\n";
    std::cout << "Encrypted file processed: " << options.inputPath.string() << "\n";
    std::cout << "Decrypted to " << options.outputPath.string() << "\n";
    return {};
}
