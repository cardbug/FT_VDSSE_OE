/*
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 *
 */

#ifndef FT_VDSSE_UTIL_H
#define FT_VDSSE_UTIL_H

#include <iostream>
#include <string>
// #include <time.h>
#include <mbedtls/sha256.h>

namespace FT_VDSSE
{

    class Util
    {

    public:
        static std::string H1(const std::string message);

        static std::string H2(const std::string message);

        static std::string Xor(const std::string s1, const std::string s2);

        //static double getCurrentTime();

        // static double getCurrentTime();
    };

} // namespace FT_VDSSE

#endif // FT_VDSSE_UTIL_H
