#include "functions.h"
#include "options.h"
#include "result.h"

#include <iostream>

int main(const int argc, char** argv) {
    const auto optionsResult = options::parseArguments(argc, argv);
    if (!optionsResult) {
        std::cerr << "Error: " << optionsResult.error() << '\n';
        return 1;
    }
    const auto& optionsVariant = *optionsResult;

    if (std::holds_alternative<options::HelpRequested>(*optionsResult)) {
        return 0;
    }

    result::Status status;
    if (const auto* encryptOptions = std::get_if<options::EncryptOptions>(&optionsVariant)) {
        status = runEncrypt(*encryptOptions);
    } else if (const auto* decryptOptions = std::get_if<options::DecryptOptions>(&optionsVariant)) {
        status = runDecrypt(*decryptOptions);
    } else {
        return 1; // Should not happen
    }

    if (!status) {
        std::cerr << "Error: " << status.error() << '\n';
        return 2;
    }

    return 0;
}
