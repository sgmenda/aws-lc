#include "test_extra.hpp"

#include <openssl/cipher.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>

std::string MAC_TEST_VECTOR_PATH = TEST_VECTOR_PATH + "mac/";

/** Abstract class for Rooterberg's MAC API */
class RooterbergMac {
 public:
  virtual ~RooterbergMac() = default;
  std::string test_name;
  /** Size of MAC digest in bits */
  virtual unsigned long MacSize() const = 0;
  virtual bool OneShotMAC(std::vector<uint8_t> &macd,
                          const std::vector<uint8_t> &key,
                          const std::vector<uint8_t> &msg) const = 0;
};

/** tests HMAC with given digest */
class RooterbergHmac : public RooterbergMac {
 public:
  std::string test_name;
  const EVP_MD *(*digest)(void);
  RooterbergHmac(std::string name, const EVP_MD *(*md)(void))
      : test_name(name), digest(md) {};
  unsigned long MacSize() const override {
    return (8 * EVP_MD_size(digest()));  // HMAC size = digest size
  }
  bool OneShotMAC(std::vector<uint8_t> &macd, const std::vector<uint8_t> &key,
                  const std::vector<uint8_t> &msg) const override {
    unsigned out_len = 0;
    bool res = HMAC(digest(), key.data(), key.size(), msg.data(), msg.size(),
                    macd.data(), &out_len);
    res &= (macd.size() == out_len);
    return res;
  }
};

/** tests HMAC with given digest */
class RooterbergCmac : public RooterbergMac {
 public:
  std::string test_name;
  const EVP_CIPHER *(*cipher)(void);
  RooterbergCmac(std::string name, const EVP_CIPHER *(*cp)(void))
      : test_name(name), cipher(cp) {};
  unsigned long MacSize() const override {
    return (8 * 16);  // Always 16 bytes
  }
  bool OneShotMAC(std::vector<uint8_t> &macd, const std::vector<uint8_t> &key,
                  const std::vector<uint8_t> &msg) const override {
    if (macd.size() != 16) {
      return false;
    }
    return AES_CMAC(macd.data(), key.data(), key.size(), msg.data(),
                    msg.size());
  }
};

static RooterbergHmac rHMACs[] = {
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

static const RooterbergCmac rCMACs[] = {
    {"aes_cmac_128_128", EVP_aes_128_cbc},
    // {"aes_cmac_192_128", EVP_aes_192_cbc},
    {"aes_cmac_256_128", EVP_aes_256_cbc},
};

// FIXME: HmacTest and CmacTest are almost identical, refactor to avoid
// copy-paste.

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
            GetParam().MacSize());  // HMAC size = digest size

  // 2. Enumerate tests
  for (auto test_case : data["tests"]) {
    std::vector<uint8_t> key = JsonHexToBytes(test_case["key"]);
    std::vector<uint8_t> msg = JsonHexToBytes(test_case["msg"]);
    std::vector<uint8_t> mac = JsonHexToBytes(test_case["mac"]);

    std::vector<uint8_t> macd(mac.size());

    // Test one-shot API
    ASSERT_TRUE(GetParam().OneShotMAC(macd, key, msg));
    EXPECT_EQ(Bytes(mac), Bytes(macd));

    // TODO: Test incremental API?
  }
};

class RooterbergCmacTest : public testing::TestWithParam<RooterbergCmac> {};
INSTANTIATE_TEST_SUITE_P(
    All, RooterbergCmacTest, testing::ValuesIn(rCMACs),
    [](const testing::TestParamInfo<RooterbergCmac> &params) -> std::string {
      return params.param.test_name;
    });

TEST_P(RooterbergCmacTest, TestName) {
  // 0. Parse JSON file
  std::ifstream f(MAC_TEST_VECTOR_PATH + GetParam().test_name + ".json");
  ASSERT_TRUE(f.is_open()) << "failed to open test file";
  json data = json::parse(f);

  // 1. Validate algorithm params
  ASSERT_EQ(data["testType"], "Mac");
  ASSERT_EQ(data["algorithm"]["algorithmType"], "Mac");
  ASSERT_EQ(data["algorithm"]["macSize"].get<size_t>(),
            GetParam().MacSize());  // HMAC size = digest size

  // 2. Enumerate tests
  for (auto test_case : data["tests"]) {
    std::vector<uint8_t> key = JsonHexToBytes(test_case["key"]);
    std::vector<uint8_t> msg = JsonHexToBytes(test_case["msg"]);
    std::vector<uint8_t> mac = JsonHexToBytes(test_case["mac"]);

    std::vector<uint8_t> macd(mac.size());

    // Test one-shot API
    ASSERT_TRUE(GetParam().OneShotMAC(macd, key, msg));
    EXPECT_EQ(Bytes(mac), Bytes(macd));

    // TODO: Test incremental API?
  }
};
