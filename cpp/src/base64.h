#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>
typedef unsigned char BYTE;

std::string base64_encode(BYTE const* buf, unsigned int bufLen);
std::string base64_decode(std::string const&);
std::vector<BYTE> base64_decode_vector(std::string const&);

#endif
