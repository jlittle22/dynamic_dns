#ifndef SRC_AUTH_AUTH_H_
#define SRC_AUTH_AUTH_H_

#include <cstddef>
#include <span>

#include "external/mbedtls/include/mbedtls/ecdsa.h"
#include "external/mbedtls/include/mbedtls/ecp.h"

namespace dynamic_dns::auth {

static constexpr std::size_t kSignatureLengthBytes = 64;

// Client must call `mbedtls_ecp_point_free`.
mbedtls_ecp_point ReadPublicKeyFromFile(const char* file_path);

// Client must call `mbedtls_ecp_keypair_free`.
mbedtls_ecp_keypair ReadPrivateKeyFromFile(const char* file_path);

// Generates a new key pair and writes them to `private.key` and `public.key`.
void GenerateNewKeyPair();

void SignMessage(std::span<const std::byte> message,
                 const mbedtls_ecp_keypair& key_pair,
                 std::span<std::byte, kSignatureLengthBytes> signature);

// Verify message w/ key

}  // namespace dynamic_dns::auth

#endif  // SRC_AUTH_AUTH_H_
