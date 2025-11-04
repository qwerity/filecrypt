#include "file.h"

#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>

namespace file {

namespace {

std::string describeStreamState(const std::ios& stream, const std::string_view context) {
    std::ostringstream oss;
    if (!context.empty()) {
        oss << context << ": ";
    } else {
        oss << "stream operation: ";
    }

    oss << "goodbit="   << (stream.good() ? "set" : "cleared")
        << ", failbit=" << (stream.fail() ? "set" : "cleared")
        << ", badbit="  << (stream.bad()  ? "set" : "cleared")
        << ", eofbit="  << (stream.eof()  ? "set" : "cleared");

    if (stream.bad()) {
        oss << " (irrecoverable I/O error)";
    } else if (stream.fail() && !stream.eof()) {
        oss << " (operation failed before reaching EOF)";
    } else if (stream.eof()) {
        oss << " (end of file reached)";
    }

    return oss.str();
}

void logError(const std::string& message) {
    std::cerr << message << '\n';
}

result::Status streamErrorStatus(const std::ios& stream, const std::string_view context) {
    const auto message = describeStreamState(stream, context);
    logError(message);
    return result::makeError(message);
}

result::Result<std::size_t> streamErrorResult(const std::ios& stream, const std::string_view context) {
    const auto message = describeStreamState(stream, context);
    logError(message);
    return result::makeError(message);
}

constexpr std::size_t maxReadable(const std::size_t requested) {
    constexpr auto limit = static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max());
    return std::min(requested, limit);
}

}  // namespace

result::Result<std::size_t> readSome(std::istream& stream, std::span<std::byte> buffer, const std::string_view context) {
    if (buffer.empty()) {
        return std::size_t{0};
    }

    if (stream.bad()) {
        return streamErrorResult(stream, context);
    }

    const auto requestSize = static_cast<std::streamsize>(maxReadable(buffer.size()));
    stream.read(reinterpret_cast<char*>(buffer.data()), requestSize);
    const auto bytesRead = static_cast<std::size_t>(stream.gcount());

    if (stream.bad()) {
        return streamErrorResult(stream, context);
    }

    if (stream.fail()) {
        if (stream.eof()) {
            stream.clear(stream.rdstate() & ~std::ios::failbit);
            return bytesRead;
        }
        return streamErrorResult(stream, context);
    }

    return bytesRead;
}

result::Status readExact(std::istream& stream, const std::span<std::byte> buffer, const std::string_view context) {
    std::size_t totalRead = 0;
    while (totalRead < buffer.size()) {
        auto remaining = buffer.subspan(totalRead);
        remaining = remaining.first(maxReadable(remaining.size()));
        const auto readResult = readSome(stream, remaining, context);
        if (!readResult) {
            return result::makeError(readResult.error());
        }
        const auto bytesRead = readResult.value();
        if (bytesRead == 0) {
            std::string message;
            if (!context.empty()) {
                message = std::string(context) + ": unexpected end of file";
            } else {
                message = "readExact: unexpected end of file";
            }
            logError(message);
            return result::makeError(std::move(message));
        }
        totalRead += bytesRead;
    }
    return {};
}

result::Status writeAll(std::ostream& stream, const std::span<const std::byte> buffer, const std::string_view context) {
    if (buffer.empty()) {
        return {};
    }

    if (stream.bad()) {
        return streamErrorStatus(stream, context);
    }

    std::size_t totalWritten = 0;
    while (totalWritten < buffer.size()) {
        const auto chunk = buffer.subspan(totalWritten);
        const auto requestSize = static_cast<std::streamsize>(maxReadable(chunk.size()));
        stream.write(reinterpret_cast<const char*>(chunk.data()), requestSize);

        if (stream.bad() || stream.fail()) {
            return streamErrorStatus(stream, context);
        }
        totalWritten += static_cast<std::size_t>(requestSize);
    }
    return {};
}

result::Status seek(std::istream& stream, const std::streamoff offset, const std::ios_base::seekdir dir, const std::string_view context) {
    if (stream.bad()) {
        return streamErrorStatus(stream, context);
    }
    stream.clear(stream.rdstate() & ~(std::ios::failbit | std::ios::eofbit));
    stream.seekg(offset, dir);
    if (stream.bad() || stream.fail()) {
        return streamErrorStatus(stream, context);
    }
    return {};
}

result::Status seek(std::ostream& stream, const std::streamoff offset, const std::ios_base::seekdir dir, const std::string_view context) {
    if (stream.bad()) {
        return streamErrorStatus(stream, context);
    }
    stream.clear(stream.rdstate() & ~(std::ios::failbit | std::ios::eofbit));
    stream.seekp(offset, dir);
    if (stream.bad() || stream.fail()) {
        return streamErrorStatus(stream, context);
    }
    return {};
}

}  // namespace file
