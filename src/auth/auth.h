#ifndef SRC_AUTH_AUTH_H_
#define SRC_AUTH_AUTH_H_

#include <cstddef>
#include <span>

#include "external/mbedtls/include/mbedtls/ecdsa.h"
#include "external/mbedtls/include/mbedtls/ecp.h"

namespace dynamic_dns::auth {

// Note: 2x the length of the private signing key, but it's not that simple.
// I don't understand enough of the math to actually know precisely what this
// should be.
static constexpr std::size_t kMaxSignatureLengthBytes = 72;

// Client must call `mbedtls_ecp_point_free`.
mbedtls_ecp_point ReadPublicKeyFromFile(const char* file_path);

// Client must call `mbedtls_ecp_keypair_free`.
mbedtls_ecp_keypair ReadPrivateKeyFromFile(const char* file_path);

// Generates a new key pair and writes them to `private.key` and `public.key`.
void GenerateNewKeyPair();

std::size_t SignMessage(
    std::span<const std::byte> message, const mbedtls_ecp_keypair& key_pair,
    std::span<std::byte, kMaxSignatureLengthBytes> signature);

// Verify message w/ key

}  // namespace dynamic_dns::auth

#endif  // SRC_AUTH_AUTH_H_
