#pragma once

#include "options.h"
#include "result.h"

result::Status runEncrypt(const options::EncryptOptions& options);
result::Status runDecrypt(const options::DecryptOptions& options);
