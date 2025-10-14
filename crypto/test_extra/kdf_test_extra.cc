#include "openssl/digest.h"
#include "test_extra.hpp"

#include <openssl/hkdf.h>
#include <cstdint>

std::string KDF_TEST_VECTOR_PATH = TEST_VECTOR_PATH + "kdf/";


/** Abstract class for Rooterberg's KDF API */
class RooterbergKdf {
 public:
  virtual ~RooterbergKdf() = default;
  std::string test_name;
  virtual bool OneShotKDF(std::vector<uint8_t> &out,
                          const std::vector<uint8_t> &ikm,
                          const std::vector<uint8_t> &salt,
                          const std::vector<uint8_t> &info) const = 0;
  explicit RooterbergKdf(std::string name) { test_name = name; };
};

/** Tests for the abstract RooterbergKdf */
static void RunRooterbergKdfTest(const RooterbergKdf *param) {
  // 0. Parse JSON file
  std::ifstream f(KDF_TEST_VECTOR_PATH + param->test_name + ".json");
  ASSERT_TRUE(f.is_open()) << "failed to open test file";
  json data = json::parse(f);

  // 1. Validate algorithm params
  ASSERT_EQ(data["testType"], "Hkdf");
  ASSERT_EQ(data["algorithm"]["algorithmType"], "Hkdf");

  // 2. Enumerate tests
  for (auto test_case : data["tests"]) {
  std::vector<uint8_t> ikm = JsonHexToBytes(test_case["ikm"]);
  std::vector<uint8_t> salt = JsonHexToBytes(test_case["salt"]);
  std::vector<uint8_t> info = JsonHexToBytes(test_case["info"]);
  EXPECT_TRUE(test_case["outLen"].is_number_unsigned());
  uint64_t outLen = JsonValueToUint(test_case["outLen"]);
  std::vector<uint8_t> okm = JsonHexToBytes(test_case["okm"]);
  EXPECT_EQ(okm.size(), outLen);

  std::vector<uint8_t> out(okm.size());

  // Test one-shot API
  ASSERT_TRUE(param->OneShotKDF(out, ikm, salt, info));
  EXPECT_EQ(Bytes(okm), Bytes(out));

  // TODO: Test incremental API?
  }
}


/** Tests HKDF with given digest */
class RooterbergHkdf : public RooterbergKdf {
 public:
  const EVP_MD *(*digest)(void);

  RooterbergHkdf(std::string name, const EVP_MD *(*md)(void))
      : RooterbergKdf(name), digest(md) {};
  bool OneShotKDF(std::vector<uint8_t> &out, const std::vector<uint8_t> &ikm,
                  const std::vector<uint8_t> &salt,
                  const std::vector<uint8_t> &info) const override {
    return HKDF(out.data(), out.size(), digest(), ikm.data(), ikm.size(),
                salt.data(), salt.size(), info.data(), info.size());
  }
};

static RooterbergHkdf rHKDFs[] = {
    {"hkdf_sha1", EVP_sha1},
    {"hkdf_sha256", EVP_sha256},
    {"hkdf_sha384", EVP_sha384},
    {"hkdf_sha512", EVP_sha512},
    {"hkdf_sha512_224", EVP_sha512_224},
    {"hkdf_sha512_256", EVP_sha512_256},
    {"hkdf_sha3_256", EVP_sha3_256},
    {"hkdf_sha3_384", EVP_sha3_384},
    {"hkdf_sha3_512", EVP_sha3_512},
};

class RooterbergHkdfTest : public testing::TestWithParam<RooterbergHkdf> {};
INSTANTIATE_TEST_SUITE_P(
    All, RooterbergHkdfTest, testing::ValuesIn(rHKDFs),
    [](const testing::TestParamInfo<RooterbergHkdf> &params) -> std::string {
      return params.param.test_name;
    });
TEST_P(RooterbergHkdfTest, TestName) { RunRooterbergKdfTest(&GetParam()); };
