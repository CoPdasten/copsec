#include "shm_guard.hpp"

#include <openssl/hmac.h>

#include <cstdlib>

namespace copsec {

ShmGuard::ShmGuard(std::string key) : key_(std::move(key)) {
    if (key_.empty()) {
        if (const char* configured_key = std::getenv("COPSEC_SHM_HMAC_KEY")) key_ = configured_key;
    }
}

bool ShmGuard::configured() const { return !key_.empty(); }

ShmGuard::Digest ShmGuard::sign(const void* data, std::size_t size) const {
    Digest digest{};
    unsigned int output_size = 0;
    HMAC(EVP_sha256(), key_.data(), static_cast<int>(key_.size()),
         static_cast<const unsigned char*>(data), size, digest.data(), &output_size);
    return digest;
}

bool ShmGuard::verify(const void* data, std::size_t size, const Digest& expected) const {
    const auto actual = sign(data, size);
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < digest_size; ++i) difference |= actual[i] ^ expected[i];
    return configured() && difference == 0;
}

} // namespace copsec