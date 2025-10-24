#pragma once

#include <expected>
#include <string>

namespace result {

template <typename T>
using Result = std::expected<T, std::string>;

inline std::unexpected<std::string> makeError(std::string message) {
    return std::unexpected<std::string>(std::move(message));
}

using Status = Result<void>;

}  // namespace result
