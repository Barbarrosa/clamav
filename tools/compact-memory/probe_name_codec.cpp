/* SPDX-License-Identifier: GPL-2.0-only
 * Standalone diagnostic for the pinned OptFSST author's implementation.
 * Not linked into ClamAV. Input: engine_census length-prefixed name export.
 */
#include "fsst.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) return 2;
    std::vector<std::string> strings;
    unsigned char header[4];
    size_t raw = 0, maxlen = 0;
    while (in.read((char *)header, 4)) {
        uint32_t n = uint32_t(header[0]) | uint32_t(header[1]) << 8 |
                     uint32_t(header[2]) << 16 | uint32_t(header[3]) << 24;
        std::string s(n, '\0');
        if (!in.read(s.data(), n)) return 3;
        raw += n + 1; maxlen = std::max(maxlen, size_t(n + 1));
        strings.emplace_back(std::move(s));
    }
    if (!in.eof() || in.gcount() != 0) return 3;
    std::vector<size_t> lengths, encoded_lengths(strings.size());
    std::vector<const unsigned char *> pointers;
    std::vector<unsigned char *> encoded(strings.size());
    for (const auto &s : strings) {
        lengths.push_back(s.size() + 1);
        pointers.push_back((const unsigned char *)s.c_str());
    }
    std::vector<unsigned char> output(2 * raw + 7), decoded(maxlen + 32);
    for (unsigned flags : {0u, 15u}) {
        fsst_options_t options{flags};
        auto start = std::chrono::steady_clock::now();
        auto *encoder = Optfsst_create(strings.size(), lengths.data(), pointers.data(), 1, &options);
        if (!encoder) return 4;
        auto built = std::chrono::steady_clock::now();
        size_t count = Optfsst_compress(encoder, strings.size(), lengths.data(), pointers.data(),
                                      output.size(), output.data(), encoded_lengths.data(),
                                      encoded.data(), &options);
        if (count != strings.size()) return 5;
        auto compressed = std::chrono::steady_clock::now();
        auto decoder = fsst_decoder(encoder);
        size_t payload = 0;
        for (size_t i = 0; i < count; i++) {
            size_t n = fsst_decompress(&decoder, encoded_lengths[i], encoded[i], decoded.size(), decoded.data());
            if (n != lengths[i] || std::memcmp(decoded.data(), pointers[i], n)) return 6;
            payload += encoded_lengths[i];
        }
        unsigned char table[FSST_MAXHEADER];
        unsigned table_bytes = fsst_export(encoder, table);
        auto seconds = [](auto a, auto b) {return std::chrono::duration<double>(b - a).count();};
        std::cout << "{\"codec\":\"" << (flags ? "OptFSST" : "FSST")
                  << "\",\"names\":" << count << ",\"raw_with_nul\":" << raw
                  << ",\"compressed_payload\":" << payload << ",\"serialized_table\":" << table_bytes
                  << ",\"resident_decoder\":" << sizeof(decoder)
                  << ",\"u32_offsets\":" << 4 * (count + 1)
                  << ",\"encoded_plus_index_plus_decoder\":" << payload + 4 * (count + 1) + sizeof(decoder)
                  << ",\"train_seconds\":" << seconds(start, built)
                  << ",\"encode_seconds\":" << seconds(built, compressed)
                  << ",\"roundtrip_verified\":true}" << std::endl;
        fsst_destroy(encoder);
    }
}
