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

// Combines a private and public key into a single key pair (populated in
// `private_key`). Validates that the two keys are in fact a correct pair.
void SetAndValidatePublicKeyInKeyPair(mbedtls_ecp_keypair& private_key,
                                      const mbedtls_ecp_point& public_key);

// Generates a new key pair and writes them to `private.key` and `public.key`.
void GenerateNewKeyPair();

// Signs `message` using the private / public `key_pair`. The signatue is
// written to `signature`. This function returns the length of the signature
// in bytes.
std::size_t SignMessage(
    std::span<const std::byte> message, const mbedtls_ecp_keypair& key_pair,
    std::span<std::byte, kMaxSignatureLengthBytes> signature);

// Returns `true` if the `message` and `signature` are congruent with
// `public_key`. Returns false otherwise.
bool IsMessageAuthentic(std::span<const std::byte> message,
                        std::span<const std::byte> signature,
                        const mbedtls_ecp_point& public_key);

// Verify message w/ key

}  // namespace dynamic_dns::auth

#endif  // SRC_AUTH_AUTH_H_
