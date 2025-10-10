#ifndef HEADER_CRYPTO_TEST_EXTRA_H
#define HEADER_CRYPTO_TEST_EXTRA_H

#include <stdint.h>

#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "../test/test_util.h"

static std::string TEST_VECTOR_PATH = "./../../third_party/Rooterberg/test_vectors/";

static std::vector<uint8_t> JsonHexToBytes(nlohmann::basic_json<> in) {
  return HexToBytes(in.get<std::string>().c_str());
}

#endif  // HEADER_CRYPTO_TEST_EXTRA_H
