#include "gtest/gtest.h"
#include "openssl/evp.h"
#include "openssl/nid.h"
#include "test_extra.hpp"

#include <openssl/experimental/kem_deterministic_api.h>
#include <cstddef>

std::string KEM_TEST_VECTOR_PATH =
    "./../../third_party/wycheproof/testvectors_v1/";

struct WycheproofKem {
  const char test_name[42];
  const int nid;
};

static const WycheproofKem wKEMs[] = {
    {"mlkem_768_test", NID_MLKEM768},
};


class WycheproofKemTest : public testing::TestWithParam<WycheproofKem> {};

INSTANTIATE_TEST_SUITE_P(All, WycheproofKemTest, testing::ValuesIn(wKEMs),
                         [](const testing::TestParamInfo<WycheproofKem> &params)
                             -> std::string { return params.param.test_name; });

TEST_P(WycheproofKemTest, TestName) {
  /* Adapted from crypto/evp_extra/evp_extra_test.cc */

  // 0. Parse JSON file
  std::string filename = KEM_TEST_VECTOR_PATH + GetParam().test_name + ".json";
  std::ifstream f(filename);
  ASSERT_TRUE(f.is_open()) << "failed to open test file: " << filename;
  json data = json::parse(f);

  // 1. Validate algorithm
  ASSERT_EQ(data["algorithm"], "ML-KEM");

  // 2. Enumerate the first subtest: check Decaps isn't using strcmp
  //    https://github.com/C2SP/CCTV/tree/main/ML-KEM#strcmp-vectors
  auto MLKEMTest = data["testGroups"][0];
  ASSERT_EQ(MLKEMTest["type"], "MLKEMTest");
  ASSERT_EQ(MLKEMTest["parameterSet"], "ML-KEM-768");

  for (auto test_case : MLKEMTest["tests"]) {
    /** the keygen seed denoted d in Algorithm 13 in FIPS 203 */
    std::vector<uint8_t> seed = JsonHexToBytes(test_case["seed"]);
    /** the encapsulation key */
    std::vector<uint8_t> expected_ek = JsonHexToBytes(test_case["ek"]);
    /** the ciphertext */
    std::vector<uint8_t> ct = JsonHexToBytes(test_case["c"]);
    /** the shared secret */
    std::vector<uint8_t> expected_ss = JsonHexToBytes(test_case["K"]);

    EXPECT_TRUE(test_case["result"].is_string());
    bool result = JsonValueToResult(test_case["result"]);

    bssl::UniquePtr<EVP_PKEY_CTX> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, nullptr));
    EXPECT_TRUE(ctx);
    EXPECT_TRUE(EVP_PKEY_CTX_kem_set_params(ctx.get(), NID_MLKEM768));
    EXPECT_TRUE(EVP_PKEY_keygen_init(ctx.get()));

    EVP_PKEY *raw = nullptr;
    size_t seed_len = seed.size();
    EXPECT_TRUE(
        EVP_PKEY_keygen_deterministic(ctx.get(), &raw, seed.data(), &seed_len));
    EXPECT_TRUE(raw);

    bssl::UniquePtr<EVP_PKEY> pkey(raw);
    ctx.reset(EVP_PKEY_CTX_new(pkey.get(), nullptr));
    ASSERT_TRUE(pkey);

    size_t ek_len = expected_ek.size();
    size_t ss_len = expected_ss.size();

    std::vector<uint8_t> ek(ek_len);
    std::vector<uint8_t> ss(ss_len);

    EVP_PKEY_get_raw_public_key(pkey.get(), ek.data(), &ek_len);
    ASSERT_EQ(Bytes(expected_ek), Bytes(ek));

    ASSERT_EQ(result, EVP_PKEY_decapsulate(ctx.get(), ss.data(), &ss_len,
                                           ct.data(), ct.size()));
    ASSERT_EQ(Bytes(expected_ss), Bytes(ss));
  }

  // 3. Enumerate the second subtest: modulus overflow during Encaps
  //    https://github.com/C2SP/CCTV/tree/main/ML-KEM#bad-encapsulation-keys
  auto MLKEMEncapsTest = data["testGroups"][1];
  ASSERT_EQ(MLKEMEncapsTest["type"], "MLKEMEncapsTest");
  ASSERT_EQ(MLKEMEncapsTest["parameterSet"], "ML-KEM-768");

  for (auto test_case : MLKEMEncapsTest["tests"]) {
    /** the encapsulation seed denoted m in Algorithm 20 in FIPS 203 */
    std::vector<uint8_t> m = JsonHexToBytes(test_case["m"]);
    /** the encapsulation key */
    std::vector<uint8_t> ek = JsonHexToBytes(test_case["ek"]);

    EXPECT_TRUE(test_case["result"].is_string());
    bool result = JsonValueToResult(test_case["result"]);

    size_t m_len = m.size();

    size_t ss_len = 32;
    std::vector<uint8_t> ss(ss_len);
    size_t ct_len = 1088;
    std::vector<uint8_t> ct(ct_len);

    bssl::UniquePtr<EVP_PKEY> pkey_ek(
        EVP_PKEY_kem_new_raw_public_key(GetParam().nid, ek.data(), ek.size()));
    bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(pkey_ek.get(), nullptr));
    EXPECT_TRUE(ctx);
    ASSERT_EQ(result, EVP_PKEY_encapsulate_deterministic(
                          ctx.get(), ct.data(), &ct_len, ss.data(), &ss_len,
                          m.data(), &m_len));
  }
};
