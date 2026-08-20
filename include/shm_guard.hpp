#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace copsec {

class ShmGuard {
public:
    static constexpr std::size_t digest_size = 32;
    using Digest = std::array<std::uint8_t, digest_size>;

    explicit ShmGuard(std::string key = {});
    bool configured() const;
    Digest sign(const void* data, std::size_t size) const;
    bool verify(const void* data, std::size_t size, const Digest& expected) const;

private:
    std::string key_;
};

} // namespace copsec