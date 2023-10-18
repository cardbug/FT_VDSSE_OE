/*
 * This project is implemented based on https://github.com/zhangzhongjun/VFSSSE
 *
 *
 */

#include "FT_VDSSE.Util.h"
#include "helloworld_t.h"

namespace FT_VDSSE
{

    std::string Util::H1(const std::string message)
    {
        unsigned char buf[32]; // SHA-256的输出长度为32字节
        std::string salt = "01";
        std::string combinedMessage = message + salt;
        mbedtls_sha256_ret((unsigned char *)combinedMessage.c_str(), combinedMessage.length(), buf, 0);
        return std::string((const char *)buf, 32);
    }

    std::string Util::H2(const std::string message)
    {
        unsigned char buf[32];
        std::string salt = "02";
        std::string combinedMessage = message + salt;
        mbedtls_sha256_ret((unsigned char *)combinedMessage.c_str(), combinedMessage.length(), buf, 0);
        return std::string((const char *)buf, 32);
    }

    std::string Util::Xor(const std::string s1, const std::string s2)
    {
        std::string result = s1;
        if (s1.length() > s2.length())
        {
            std::cout << "not sufficient size: " << s1.length() << ", " << s2.length() << std::endl;
            return "";
        }

        for (int i = 0; i < result.length(); i++)
        {
            result[i] ^= s2[i];
        }
        return result;
    }

    
}
