#include "test_extra.hpp"

#include <openssl/hmac.h>

std::string MAC_TEST_VECTOR_PATH = TEST_VECTOR_PATH + "mac/";

/** tests HMAC with given digest */
struct RooterbergHmac {
  const char test_name[42];
  const EVP_MD *(*digest)(void);
};

static const RooterbergHmac rHMACs[] = {
    {"hmac_sha1_160", EVP_sha1},
    {"hmac_sha256_256", EVP_sha256},
    {"hmac_sha384_384", EVP_sha384},
    {"hmac_sha512_512", EVP_sha512},
    {"hmac_sha512_224_224", EVP_sha512_224},
    {"hmac_sha512_256_256", EVP_sha512_256},
    {"hmac_sha3_256_256", EVP_sha3_256},
    {"hmac_sha3_384_384", EVP_sha3_384},
    {"hmac_sha3_512_512", EVP_sha3_512},
};


class RooterbergHmacTest : public testing::TestWithParam<RooterbergHmac> {};

INSTANTIATE_TEST_SUITE_P(
    All, RooterbergHmacTest, testing::ValuesIn(rHMACs),
    [](const testing::TestParamInfo<RooterbergHmac> &params) -> std::string {
      return params.param.test_name;
    });

TEST_P(RooterbergHmacTest, TestName) {
  // 0. Parse JSON file
  std::ifstream f(MAC_TEST_VECTOR_PATH + GetParam().test_name + ".json");
  ASSERT_TRUE(f.is_open()) << "failed to open test file";
  json data = json::parse(f);

  // 1. Validate algorithm params
  ASSERT_EQ(data["testType"], "Mac");
  ASSERT_EQ(data["algorithm"]["algorithmType"], "Mac");
  ASSERT_EQ(data["algorithm"]["macSize"].get<size_t>(),
            8 * EVP_MD_size(GetParam().digest()));  // HMAC size = digest size

  // 2. Enumerate tests
  for (auto test_case : data["tests"]) {
    std::vector<uint8_t> key = JsonHexToBytes(test_case["key"]);
    std::vector<uint8_t> msg = JsonHexToBytes(test_case["msg"]);
    std::vector<uint8_t> mac = JsonHexToBytes(test_case["mac"]);

    std::vector<uint8_t> macd(mac.size());

    unsigned out_len = 0;
    ASSERT_TRUE(HMAC(GetParam().digest(), key.data(), key.size(), msg.data(),
                     msg.size(), macd.data(), &out_len));
    ASSERT_LE(mac.size(), out_len);
    EXPECT_EQ(Bytes(mac), Bytes(macd));
  }
};
