#include <stdint.h>
#include <string.h>

#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>

struct RooterbergAead {
  const char test_name[42];
  const EVP_AEAD *(*func)(void);
};

static const struct RooterbergAead rAEADs[] = {
    {"aes_gcm_128_96_128", EVP_aead_aes_128_gcm},
    {"aes_gcm_256_96_128", EVP_aead_aes_256_gcm},
};


class RooterbergAeadTest : public testing::TestWithParam<RooterbergAead> {};

INSTANTIATE_TEST_SUITE_P(
    All, RooterbergAeadTest, testing::ValuesIn(rAEADs),
    [](const testing::TestParamInfo<RooterbergAead> &params) -> std::string {
      return params.param.test_name;
    });

TEST_P(RooterbergAeadTest, TestName) {
  // 0. Parse JSON file
  // FIXME: replace hardcoded path
  std::ifstream f(
      "./../../third_party/Rooterberg/test_vectors/aead/"
      "aes_gcm_128_96_128.json");
  if (!f.is_open()) {
    std::cerr << "failed to open" << std::endl;
  }
  json data = json::parse(f, nullptr, false);
  if (data.is_discarded()) {
    std::cerr << "parse error" << std::endl;
  }

  // 1. Validate and set algorithm params
  ASSERT_EQ(data["testType"], "Aead");
  std::cout << data["algorithm"] << std::endl;

  // 2. Enumerate tests
};
