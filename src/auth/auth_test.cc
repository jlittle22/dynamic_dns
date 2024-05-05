#include "src/auth/auth.h"

#include <cstdio>
#include <iomanip>
#include <ios>
#include <span>
#include <string>

#include "external/mbedtls/include/mbedtls/ctr_drbg.h"
#include "external/mbedtls/include/mbedtls/entropy.h"
#include "gtest/gtest.h"
#include "src/common/assert.h"

namespace dynamic_dns::auth {
namespace {

[[maybe_unused]] void PrintBytesAsHex(std::span<const std::byte> bytes) {
  std::ios_base::fmtflags f(std::cerr.flags());

  std::cerr << "print " << bytes.size() << " bytes..." << std::endl;
  // 8 bytes per row
  std::size_t num_rows = (bytes.size() + 8 - 1) / 8;
  for (std::size_t i = 0; i < num_rows; ++i) {
    for (std::size_t j = 0; j < 8; ++j) {
      std::size_t true_index = (i * 8) + j;
      if (true_index >= bytes.size()) break;
      std::cerr << " " << std::setw(2) << std::setfill('0') << std::hex
                << static_cast<int>(bytes[true_index]);
    }
    std::cerr << std::endl;
  }
  std::cerr.flags(f);
}

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
    ASSERT(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0,
           "Failed to load ECP group.");

    ASSERT_EQ(mbedtls_ecp_check_pubkey(&group, &pub_key), 0);
    ASSERT_EQ(mbedtls_ecp_set_public_key(MBEDTLS_ECP_DP_SECP256R1, &priv_key,
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

  SetAndValidatePublicKeyInKeyPair(priv_key, pub_key);

  constexpr const char* kMessage = "Hello my name is Jake.";
  std::byte signature[kMaxSignatureLengthBytes];

  std::size_t sig_size = SignMessage(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(kMessage),
                                 strlen(kMessage)),
      priv_key, std::span(signature));

  std::string corrupted_message = kMessage;
  corrupted_message[0] = 'J';
  std::byte signature_of_corrupted_message[kMaxSignatureLengthBytes];

  std::size_t corrupt_sig_size = SignMessage(
      std::span<const std::byte>(
          reinterpret_cast<const std::byte*>(corrupted_message.c_str()),
          corrupted_message.size()),
      priv_key, std::span(signature_of_corrupted_message));

  mbedtls_ecp_keypair_free(&priv_key);
  mbedtls_ecp_point_free(&pub_key);

  if (corrupt_sig_size != sig_size) {
    SUCCEED();
    return;
  }

  for (std::size_t i = 0; i < sig_size; ++i) {
    if (signature[i] != signature_of_corrupted_message[i]) {
      SUCCEED();
      return;
    }
  }

  FAIL();
}
}  // namespace
}  // namespace dynamic_dns::auth