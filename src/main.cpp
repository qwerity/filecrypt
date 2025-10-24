#include "functions.h"
#include "options.h"
#include "result.h"

#include <iostream>

int main(int argc, char** argv) {
    const auto optionsResult = options::parseArguments(argc, argv);
    if (!optionsResult) {
        std::cerr << "Error: " << optionsResult.error() << '\n';
        return 1;
    }
    const auto& optionsVariant = *optionsResult;

    result::Status status;
    if (const auto* encryptOptions = std::get_if<options::EncryptOptions>(&optionsVariant)) {
        status = runEncrypt(*encryptOptions);
    } else {
        status = runDecrypt(std::get<options::DecryptOptions>(optionsVariant));
    }
    if (!status) {
        std::cerr << "Error: " << status.error() << '\n';
        return 1;
    }
    return 0;
}
