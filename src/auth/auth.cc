#include "src/auth/auth.h"

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <span>
#include <vector>

#include "external/mbedtls/include/mbedtls/ctr_drbg.h"
#include "external/mbedtls/include/mbedtls/ecp.h"
#include "external/mbedtls/include/mbedtls/entropy.h"
#include "external/mbedtls/include/mbedtls/md.h"
#include "external/mbedtls/include/mbedtls/sha256.h"
#include "src/common/assert.h"

namespace dynamic_dns::auth {
namespace {
constexpr int kHexRadix = 16;
constexpr const char* kHexPrefix = "0x";
constexpr const char* kPrivateKeyOutputFile = "private.key";
constexpr const char* kPublicKeyOutputFile = "public.key";

constexpr std::size_t kSha256Bytes = 32;

class EcpGroup {
 public:
  // Fucking w this function probably invalidates any previously-generated keys.
  EcpGroup() {
    mbedtls_ecp_group_init(&group_);
    ASSERT(mbedtls_ecp_group_load(&group_, MBEDTLS_ECP_DP_SECP256R1) == 0,
           "Failed to load ECP group.");
  }

  ~EcpGroup() { mbedtls_ecp_group_free(&group_); }

  mbedtls_ecp_group* Get() { return &group_; }

 private:
  mbedtls_ecp_group group_ = {};
};

EcpGroup ecp_group;

void Hash(std::span<const std::byte> message,
          std::span<std::byte, kSha256Bytes> output) {
  int ret = mbedtls_sha256(
      reinterpret_cast<const unsigned char*>(message.data()),
      message.size_bytes(), reinterpret_cast<unsigned char*>(output.data()),
      /*is224=*/0);
  ASSERT(ret == 0, "Failed to hash message.");
}

void WritePublicKeyToFile(const mbedtls_ecp_point& key) {
  // Write once to retrieve buffer size.
  std::size_t write_size = 0;
  mbedtls_ecp_point_write_binary(ecp_group.Get(), &key,
                                 MBEDTLS_ECP_PF_UNCOMPRESSED, &write_size,
                                 nullptr, 0);

  unsigned char* buffer = new unsigned char[write_size];
  ASSERT(buffer != nullptr, "Failed to allocate public key buffer.");

  int ret = mbedtls_ecp_point_write_binary(ecp_group.Get(), &key,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &write_size, buffer, write_size);
  ASSERT(ret == 0, "Failed to write public key to binary.");

  auto out_file =
      std::fstream(kPublicKeyOutputFile, std::ios::out | std::ios::binary);
  out_file.write(reinterpret_cast<char*>(buffer), write_size);
  out_file.close();

  delete[] buffer;
}

void WritePrivateKeyToFile(const mbedtls_ecp_keypair& key) {
  unsigned char* buffer = new unsigned char[MBEDTLS_ECP_MAX_BYTES];
  ASSERT(buffer != nullptr, "Failed to allocate private key buffer.");

  std::size_t write_size = 0;
  int ret = mbedtls_ecp_write_key_ext(&key, &write_size, buffer,
                                      MBEDTLS_ECP_MAX_BYTES);
  ASSERT(ret == 0, "Failed to write private key to buffer.");

  auto out_file =
      std::fstream(kPrivateKeyOutputFile, std::ios::out | std::ios::binary);
  out_file.write(reinterpret_cast<char*>(buffer), write_size);
  out_file.close();

  delete[] buffer;
}

}  // namespace

mbedtls_ecp_point ReadPublicKeyFromFile(const char* file_path) {
  std::ifstream stream(file_path, std::ios::in | std::ios::binary);
  std::vector<unsigned char> contents((std::istreambuf_iterator<char>(stream)),
                                      std::istreambuf_iterator<char>());

  mbedtls_ecp_point public_key;
  mbedtls_ecp_point_init(&public_key);

  int ret = mbedtls_ecp_point_read_binary(ecp_group.Get(), &public_key,
                                          contents.data(), contents.size());
  ASSERT(ret == 0, "Failed to read public key from file.");

  return public_key;
}

mbedtls_ecp_keypair ReadPrivateKeyFromFile(const char* file_path) {
  std::ifstream stream(file_path, std::ios::in | std::ios::binary);
  std::vector<unsigned char> contents((std::istreambuf_iterator<char>(stream)),
                                      std::istreambuf_iterator<char>());
  ASSERT(contents.size() > 0, "Failed to read data from private key file.");

  mbedtls_ecp_keypair key = {};
  mbedtls_ecp_keypair_init(&key);

  mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, contents.data(),
                       contents.size());
  return key;
}

void GenerateNewKeyPair() {
  // Initialize private key destination.
  mbedtls_ecp_keypair key_pair;
  mbedtls_ecp_keypair_init(&key_pair);

  // Initialize entropy context.
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  // Initialize RNG context.
  mbedtls_ctr_drbg_context rng_context = {};
  mbedtls_ctr_drbg_init(&rng_context);

  // Seed the RNG context.
  int ret = mbedtls_ctr_drbg_seed(&rng_context, mbedtls_entropy_func, &entropy,
                                  nullptr, 0);
  ASSERT(ret == 0, "Failed to seed RNG.");

  ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key_pair,
                            mbedtls_ctr_drbg_random, &rng_context);
  ASSERT(ret == 0, "Failed to generate key pair.");

  mbedtls_ecp_point public_key = {};
  mbedtls_ecp_point_init(&public_key);

  ret = mbedtls_ecp_export(&key_pair, nullptr, nullptr, &public_key);
  ASSERT(ret == 0, "Failed to export key pair components.");

  WritePrivateKeyToFile(key_pair);
  WritePublicKeyToFile(public_key);

  mbedtls_ecp_keypair_free(&key_pair);
  mbedtls_ecp_point_free(&public_key);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&rng_context);
}

void SetAndValidatePublicKeyInKeyPair(mbedtls_ecp_keypair& private_key,
                                      const mbedtls_ecp_point& public_key) {
  mbedtls_ecp_group group;
  mbedtls_ecp_group_init(&group);
  ASSERT(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0,
         "Failed to load ECP group.");

  ASSERT(mbedtls_ecp_check_pubkey(&group, &public_key) == 0,
         "Public key is invalid.");
  ASSERT(mbedtls_ecp_set_public_key(MBEDTLS_ECP_DP_SECP256R1, &private_key,
                                    &public_key) == 0,
         "Can't set public key in key pair.");

  // Initialize entropy context.
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  // Initialize RNG context.
  mbedtls_ctr_drbg_context rng_context = {};
  mbedtls_ctr_drbg_init(&rng_context);

  // Seed the RNG context.
  int ret = mbedtls_ctr_drbg_seed(&rng_context, mbedtls_entropy_func, &entropy,
                                  nullptr, 0);
  ASSERT(ret == 0, "Failed to seed RNG.");

  ASSERT(mbedtls_ecp_check_pub_priv(&private_key, &private_key,
                                    mbedtls_ctr_drbg_random, &rng_context) == 0,
         "Public key isn't consistent with private key.");

  mbedtls_ecp_group_free(&group);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&rng_context);
}

std::size_t SignMessage(
    std::span<const std::byte> message, const mbedtls_ecp_keypair& key_pair,
    std::span<std::byte, kMaxSignatureLengthBytes> signature) {
  mbedtls_ecdsa_context signing_context = {};
  mbedtls_ecdsa_init(&signing_context);

  int ret = mbedtls_ecdsa_from_keypair(&signing_context, &key_pair);
  ASSERT(ret == 0, "Failed to create ECDSA context from keypair.");

  // Initialize entropy context.
  mbedtls_entropy_context entropy = {};
  mbedtls_entropy_init(&entropy);

  // Initialize RNG context.
  mbedtls_ctr_drbg_context rng_context = {};
  mbedtls_ctr_drbg_init(&rng_context);

  // Seed the RNG context.
  ret = mbedtls_ctr_drbg_seed(&rng_context, mbedtls_entropy_func, &entropy,
                              nullptr, 0);
  ASSERT(ret == 0, "Failed to seed RNG.");

  std::byte hash_buffer[kSha256Bytes];
  Hash(message, std::span<std::byte, kSha256Bytes>(hash_buffer));

  std::size_t write_bytes = 0;
  ret = mbedtls_ecdsa_write_signature(
      &signing_context, MBEDTLS_MD_SHA256,
      reinterpret_cast<unsigned char*>(hash_buffer), kSha256Bytes,
      reinterpret_cast<unsigned char*>(signature.data()),
      signature.size_bytes(), &write_bytes, mbedtls_ctr_drbg_random,
      &rng_context);
  ASSERT(ret == 0, "Failed to write signature.");

  mbedtls_ecdsa_free(&signing_context);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&rng_context);

  return write_bytes;
}

bool IsMessageAuthentic(std::span<const std::byte> message,
                        std::span<const std::byte> signature,
                        const mbedtls_ecp_point& public_key) {
  mbedtls_ecdsa_context signing_context = {};
  mbedtls_ecdsa_init(&signing_context);

  // Verify the public key belongs to the group.
  mbedtls_ecp_group group;
  mbedtls_ecp_group_init(&group);
  ASSERT(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0,
         "Failed to load ECP group.");

  ASSERT(mbedtls_ecp_check_pubkey(&group, &public_key) == 0,
         "Public key is invalid for the group.");

  mbedtls_ecp_keypair public_key_as_pair = {};
  mbedtls_ecp_keypair_init(&public_key_as_pair);

  ASSERT(mbedtls_ecp_set_public_key(MBEDTLS_ECP_DP_SECP256R1,
                                    &public_key_as_pair, &public_key) == 0,
         "Can't set public key in key pair.");

  int ret = mbedtls_ecdsa_from_keypair(&signing_context, &public_key_as_pair);
  ASSERT(ret == 0, "Failed to create ECDSA context from keypair.");

  // Compute the message's hash.
  std::byte hash_buffer[kSha256Bytes];
  Hash(message, std::span<std::byte, kSha256Bytes>(hash_buffer));

  ret = mbedtls_ecdsa_read_signature(
      &signing_context, reinterpret_cast<unsigned char*>(hash_buffer),
      kSha256Bytes, reinterpret_cast<const unsigned char*>(signature.data()),
      signature.size());

  mbedtls_ecdsa_free(&signing_context);
  mbedtls_ecp_keypair_free(&public_key_as_pair);
  mbedtls_ecp_group_free(&group);

  return ret == 0;
}
}  // namespace dynamic_dns::auth
