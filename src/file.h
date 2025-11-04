#pragma once

#include "result.h"

#include <cstddef>
#include <ios>
#include <istream>
#include <ostream>
#include <span>
#include <string_view>

namespace file {

result::Result<std::size_t> readSome(std::istream& stream, std::span<std::byte> buffer, std::string_view context = {});
result::Status readExact(std::istream& stream, std::span<std::byte> buffer, std::string_view context = {});
result::Status writeAll(std::ostream& stream, std::span<const std::byte> buffer, std::string_view context = {});
result::Status seek(std::istream& stream, std::streamoff offset, std::ios_base::seekdir dir, std::string_view context = {});
result::Status seek(std::ostream& stream, std::streamoff offset, std::ios_base::seekdir dir, std::string_view context = {});

}  // namespace file

