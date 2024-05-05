#include "src/auth/auth.h"

#include <cstdio>
#include <span>
#include <string>

#include "external/mbedtls/include/mbedtls/ctr_drbg.h"
#include "external/mbedtls/include/mbedtls/entropy.h"
#include "gtest/gtest.h"
#include "src/common/assert.h"

namespace dynamic_dns::auth {
namespace {

constexpr bool kGenerateNewKeyPair = false;

// Not a real test. Just used for manually generating key pairs.
TEST(AuthTest, TestGenerateNewKeyPair) {
  if constexpr (kGenerateNewKeyPair) {
    GenerateNewKeyPair();
  } else {
    mbedtls_ecp_point pub_key = ReadPublicKeyFromFile("public.key");
    mbedtls_ecp_keypair priv_key = ReadPrivateKeyFromFile("private.key");

    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    ASSERT(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519) == 0,
           "Failed to load ECP group.");

    ASSERT_EQ(mbedtls_ecp_check_pubkey(&group, &pub_key), 0);
    ASSERT_EQ(mbedtls_ecp_set_public_key(MBEDTLS_ECP_DP_CURVE25519, &priv_key,
                                         &pub_key),
              0);

    // Initialize entropy context.
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    // Initialize RNG context.
    mbedtls_ctr_drbg_context rng_context = {};
    mbedtls_ctr_drbg_init(&rng_context);

    // Seed the RNG context.
    int ret = mbedtls_ctr_drbg_seed(&rng_context, mbedtls_entropy_func,
                                    &entropy, nullptr, 0);
    ASSERT(ret == 0, "Failed to seed RNG.");

    ASSERT_EQ(mbedtls_ecp_check_pub_priv(&priv_key, &priv_key,
                                         mbedtls_ctr_drbg_random, &rng_context),
              0);

    mbedtls_ecp_keypair_free(&priv_key);
    mbedtls_ecp_point_free(&pub_key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&rng_context);
    mbedtls_ecp_group_free(&group);
  }
}

TEST(AuthTest, TestSignMessage) {
  mbedtls_ecp_point pub_key = ReadPublicKeyFromFile("public.key");
  mbedtls_ecp_keypair priv_key = ReadPrivateKeyFromFile("private.key");

  mbedtls_ecp_group group;
  mbedtls_ecp_group_init(&group);
  ASSERT(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519) == 0,
         "Failed to load ECP group.");

  ASSERT_EQ(mbedtls_ecp_check_pubkey(&group, &pub_key), 0);
  ASSERT_EQ(mbedtls_ecp_set_public_key(MBEDTLS_ECP_DP_CURVE25519, &priv_key,
                                       &pub_key),
            0);

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

  ASSERT_EQ(mbedtls_ecp_check_pub_priv(&priv_key, &priv_key,
                                       mbedtls_ctr_drbg_random, &rng_context),
            0);

  constexpr const char* kMessage = "Hello my name is Jake.";
  std::byte signature[kSignatureLengthBytes];

 SignMessage(std::span<const std::byte>(reinterpret_cast<const std::byte*>(kMessage), strlen(kMessage)),
             priv_key,
                 std::span(signature));

  mbedtls_ecp_keypair_free(&priv_key);
  mbedtls_ecp_point_free(&pub_key);
  mbedtls_ecp_group_free(&group);
}
}  // namespace
}  // namespace dynamic_dns::auth