#ifndef HEADER_CRYPTO_TEST_EXTRA_H
#define HEADER_CRYPTO_TEST_EXTRA_H

#include <stdint.h>

#include <cstdint>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "../test/test_util.h"

static std::string TEST_VECTOR_PATH = "./../../third_party/Rooterberg/test_vectors/";

static inline std::vector<uint8_t> JsonHexToBytes(nlohmann::basic_json<> in) {
  return HexToBytes(in.get<std::string>().c_str());
}

static inline uint64_t JsonValueToUint(nlohmann::basic_json<> in) {
  return in.get<uint64_t>();
}

#endif  // HEADER_CRYPTO_TEST_EXTRA_H
