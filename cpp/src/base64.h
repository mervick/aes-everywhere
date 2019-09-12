#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>
#include <stdint.h>

std::string base64_encode(uint8_t const* buf, unsigned int bufLen);
std::string base64_decode(std::string const&);
std::vector<uint8_t> base64_decode_vector(std::string const&);

#endif
