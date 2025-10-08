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

#include "../test/test_util.h"

std::string TEST_VECTOR_PATH = "./../../third_party/Rooterberg/test_vectors/";
std::string AEAD_TEST_VECTOR_PATH = TEST_VECTOR_PATH + "aead/";

static std::vector<uint8_t> JsonHexToBytes(nlohmann::basic_json<> in) {
  return HexToBytes(in.get<std::string>().c_str());
}

struct RooterbergAead {
  const char test_name[42];
  const EVP_AEAD *(*aead)(void);
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
  std::ifstream f(AEAD_TEST_VECTOR_PATH + GetParam().test_name + ".json");
  if (!f.is_open()) {
    std::cerr << "failed to open" << std::endl;
  }
  json data = json::parse(f, nullptr, false);
  if (data.is_discarded()) {
    std::cerr << "parse error" << std::endl;
  }

  // 1. Validate algorithm params
  ASSERT_EQ(data["testType"], "Aead");
  ASSERT_EQ(data["algorithm"]["algorithmType"], "Aead");
  ASSERT_EQ(data["algorithm"]["keySize"].get<size_t>(),
            8 * EVP_AEAD_key_length(GetParam().aead()));
  ASSERT_EQ(data["algorithm"]["ivSize"].get<size_t>(),
            8 * EVP_AEAD_nonce_length(GetParam().aead()));
  ASSERT_EQ(data["algorithm"]["tagSize"].get<size_t>(),
            8 * EVP_AEAD_max_overhead(GetParam().aead()));
  // TODO: find a way to verify the primitive?
  std::cout << data["algorithm"]["primitive"] << std::endl;

  // 2. Enumerate tests
  for (auto test_case : data["tests"]) {
    std::vector<uint8_t> key = JsonHexToBytes(test_case["key"]);
    std::vector<uint8_t> iv = JsonHexToBytes(test_case["iv"]);
    std::vector<uint8_t> aad = JsonHexToBytes(test_case["aad"]);
    std::vector<uint8_t> msg = JsonHexToBytes(test_case["msg"]);
    std::vector<uint8_t> ct = JsonHexToBytes(test_case["ct"]);
    std::vector<uint8_t> tag = JsonHexToBytes(test_case["tag"]);

    std::vector<uint8_t> expected_encrypted(ct);
    expected_encrypted.insert(expected_encrypted.end(), tag.begin(), tag.end());
    ASSERT_EQ(expected_encrypted.size(), ct.size() + tag.size());

    bssl::ScopedEVP_AEAD_CTX ctx;
    ASSERT_TRUE(EVP_AEAD_CTX_init_with_direction(ctx.get(), GetParam().aead(),
                                                 key.data(), key.size(),
                                                 tag.size(), evp_aead_seal));

    std::vector<uint8_t> encrypted(msg.size() +
                                   EVP_AEAD_max_overhead(GetParam().aead()));

    size_t encrypted_len = 0;
    ASSERT_TRUE(EVP_AEAD_CTX_seal(
        ctx.get(), encrypted.data(), &encrypted_len, encrypted.size(),
        iv.data(), iv.size(), msg.data(), msg.size(), aad.data(), aad.size()));
    encrypted.resize(encrypted_len);

    EXPECT_EQ(test_case["valid"].get<bool>(),
              Bytes(encrypted) == Bytes(expected_encrypted));

    ctx.Reset();
    ASSERT_TRUE(EVP_AEAD_CTX_init_with_direction(ctx.get(), GetParam().aead(),
                                                 key.data(), key.size(),
                                                 tag.size(), evp_aead_open));

    std::vector<uint8_t> decrypted(msg.size() +
                                   EVP_AEAD_max_overhead(GetParam().aead()));

    size_t decrypted_len = 0;
    int ret = EVP_AEAD_CTX_open(
        ctx.get(), decrypted.data(), &decrypted_len, decrypted.size(),
        iv.data(), iv.size(), expected_encrypted.data(),
        expected_encrypted.size(), aad.data(), aad.size());
    decrypted.resize(decrypted_len);
    EXPECT_EQ(test_case["valid"].get<bool>(), (ret == 1));
  }
};
