#include <stdio.h>
#include <string>
#include "helloworld_t.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <array>
#include <cstdint>
#include <unordered_set>
#include <openenclave/enclave.h>
#include <sys/time.h>
#include <time.h>
#include "mbedtls/aes.h"
#include <mbedtls/md5.h>
#include "mbedtls/base64.h"
#include "mbedtls_src/mbedtls_src.h"
#include "mbedtls_src/path_oram.h"
#include "FT_VDSSE.Util.h"
#include <iomanip>

#define ALIGN(n) __attribute__((aligned(n)))

#define unequal_blocks(x, y) ((((x).l ^ (y).l) | ((x).r ^ (y).r)) != 0)
#define getL(_ctx, _tz) ((_ctx)->L[_tz])
#define BPI 8
#define L_TABLE_SZ 16
#define AES_KEY_SIZE 16
#define OCB_TAG_LEN 8
#define SIZE_L 32
#define SIZE_E 24
#define SIZE_PROOF 50

using namespace FT_VDSSE;

unsigned char k_s[17] = "0123456789abcdef";
unsigned char iv_s[17] = "0123456789abcdef";

unsigned char k_p[17] = "abcdef1234567890";
unsigned char iv_p[17] = "0123456789abcdef";

unsigned char k_t[17] = "qwertyuiopasdfgh";
unsigned char iv_t[17] = "wdf3e5f7g9ahcuej";

using ORAM = PathORAM<10, 16>;
ORAM oram;
size_t blockID_counter = 0; // 初始化块ID计数器
std::map<std::string, std::vector<size_t>> key_to_blockID;

struct StringPair
{
    char key[100];
    char value[10];
};

struct StringTriple
{
    char upds[10];
    char s2[10];
    char id[10];
};

struct WC
{
    int c1;
    int c2;
};

struct UpdateRequest
{
    std::string l;
    std::string e;
    std::string proof;
};

struct KeyData {
    std::string key;
    int c1;
    int c2;

    std::string serialize() const {
        std::ostringstream oss;
        oss << key << "|";
        oss << c1 << "|";
        oss << c2 << "|";
        return oss.str();
    }

    static KeyData deserialize(const std::string& s) {
        KeyData kd;
        // std::cout << "s: " << s <<std::endl;
        std::istringstream iss(s);
        std::string item;
        std::getline(iss, kd.key, '|');
        // std::cout << "kd.key: " << kd.key <<std::endl;
        if (iss.fail()) {
        }

        std::string c1_str;
        std::string c2_str;
        std::getline(iss, c1_str, '|');
        std::getline(iss, c2_str, '|');

        try {
            kd.c1 = std::stoi(c1_str);
            kd.c2 = std::stoi(c2_str);
        } catch (const std::invalid_argument& e) {
            throw;
        }
        return kd;
    }
};

KeyData search_key_in_oram(std::string key){
    if (key_to_blockID.find(key) != key_to_blockID.end()) {
        size_t target_blockID = key_to_blockID[key][0];
        ORAM::Block read_block = oram.read(target_blockID);
        std::string read_serialized(read_block.begin(), read_block.end());
        KeyData kd = KeyData::deserialize(read_serialized);
        // host_print_char("Key found.");
        return kd;
    } else {
        KeyData empty_kd;  // 创建一个空的 KeyData 对象表示未找到
        // empty_kd.key = "Key not found.";
        empty_kd.c1=0;
        empty_kd.c2=0;
        // host_print_char("Key not found.");
        return empty_kd;
    }
}

void update_or_init_key_in_oram(KeyData kd)
{
    if (key_to_blockID.find(kd.key) != key_to_blockID.end())
    {
        // host_print_char("Key exists, update the existing block");
        size_t existing_blockID = key_to_blockID[kd.key][0];
        std::string serialized = kd.serialize();
        ORAM::Block block;
        std::memcpy(block.data(), serialized.data(), std::min(block.size(), serialized.size()));
        oram.write(existing_blockID, block); // Use the existing block ID
    }
    else
    {
        // host_print_char("Key doesn't exist, create a new block");
        std::string serialized = kd.serialize();
        ORAM::Block block;
        std::memcpy(block.data(), serialized.data(), std::min(block.size(), serialized.size()));
        oram.write(blockID_counter, block);                // Use a new block ID
        key_to_blockID[kd.key].push_back(blockID_counter); // Update the mapping
        ++blockID_counter;                                 // Increment the block ID counter for future blocks
    }
}

void set_wc_map_for_w(KeyData w_map){
    update_or_init_key_in_oram(w_map);
}

int set_c1c2(const std::string &w, int c1, int c2)
{
    KeyData kd;
    kd.key = w;
    kd.c1 = c1;
    kd.c2 = c2;
    set_wc_map_for_w(kd);
    update_or_init_key_in_oram(kd);
    return 0;
}

int get_c1(const std::string &w)
{   
    KeyData s_w = search_key_in_oram(w);
    int ret;
    std::string mes = "get_c1 -- key: " + s_w.key \
                        + " c1: " + std::to_string(s_w.c1) \
                        + " c2: " + std::to_string(s_w.c2);
    if (s_w.key != "Key not found.")
    {   
        ret = s_w.c1;
    }else{
        set_c1c2(w, 0, 0);
        ret = 0;
    }
    return ret;
}

int get_c2(const std::string &w)
{
    KeyData s_w = search_key_in_oram(w);
    int ret;
    std::string mes = "get_c1 -- key: " + s_w.key \
                        + " c1: " + std::to_string(s_w.c1) \
                        + " c2: " + std::to_string(s_w.c2);
    if (s_w.key != "Key not found.")
    {
        ret = s_w.c2;
    }else{
        set_c1c2(w, 0, 0);
        ret = 0;
    }
    return ret;
}

void readStringPairs(const std::string &input, std::vector<StringPair> &pairs)
{
    std::istringstream iss(input);
    std::string line;

    while (std::getline(iss, line, ','))
    {
        StringPair pair;
        std::istringstream lineStream(line);
        lineStream.get(pair.key, sizeof(pair.key), '|');
        lineStream.ignore(); // Ignore the '|'
        lineStream.get(pair.value, sizeof(pair.value));
        pairs.push_back(pair);
    }
}

void readStringTriple(const std::string &input, std::vector<StringTriple> &pairs)
{
    std::istringstream iss(input);
    std::string line;
    while (std::getline(iss, line, ','))
    {
        StringTriple pair;
        std::istringstream lineStream(line);
        lineStream.get(pair.upds, sizeof(pair.upds), '|');
        lineStream.ignore(); // Ignore the '|'
        lineStream.get(pair.s2, sizeof(pair.s2), '|');
        lineStream.ignore(); // Ignore the '|'
        lineStream.get(pair.id, sizeof(pair.id));

        pairs.push_back(pair);
    }
}

std::string concatenate_arguments(const std::vector<std::string> &arguments)
{
    std::string result = "[";
    for (const auto &arg : arguments)
    {
        result += arg + "], [";
    }
    result = result.substr(0, result.size() - 3);
    return result;
}

std::string ctrencrypt(const unsigned char *skey, const unsigned char *siv, const std::string plainText)
{
    e_ctx *encctx = e_allocate(NULL);
    e_init(encctx, (unsigned char *)skey, 16);
    // std::cout<<wc2<<std::endl;
    ALIGN(16) const char *cplain = plainText.c_str();
    int length = plainText.length();
    ALIGN(16) char ccipher[length];
    // encrypt_ctr(encctx, iv_s, cplain, length, ccipher);
    encrypt_ctr(encctx, iv_s, (const unsigned char *)cplain, length, (unsigned char *)ccipher);
    std::string cipher(ccipher, length);
    e_clear(encctx);
    e_free(encctx);
    return cipher;
}

std::string ctrdecrypt(const unsigned char *skey, const unsigned char *siv, const std::string cipherText)
{
    e_ctx *decctx = e_allocate(NULL);
    e_init(decctx, (unsigned char *)skey, 16);
    ALIGN(16) const char *ccipher = cipherText.c_str();
    int length = cipherText.length();
    ALIGN(16) char cplain[length];
    decrypt_ctr(decctx, iv_s, ccipher, length, cplain);
    std::string plain(cplain, length);
    e_clear(decctx);
    e_free(decctx);
    return plain;
}

std::string decrypt_aes_ecb(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    size_t blocks = ciphertext_len / 16;
    unsigned char decrypted_output[2048];
    for (size_t i = 0; i < blocks; i++) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, ciphertext + (i * 16), decrypted_output + (i * 16));
    }
    mbedtls_aes_free(&aes);
    size_t data_len = 0;
    while (data_len < ciphertext_len && decrypted_output[data_len] != '\0') {
        data_len++;
    }
    return std::string(reinterpret_cast<char*>(decrypted_output), data_len);
}

std::string calculateMD5(const char *input) {
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    size_t input_len = std::strlen(input);
    mbedtls_md5_starts_ret(&ctx);
    mbedtls_md5_update_ret(&ctx, reinterpret_cast<const unsigned char*>(input), input_len);
    unsigned char output[16];
    mbedtls_md5_finish_ret(&ctx, output);
    mbedtls_md5_free(&ctx);
    std::string md5Hash;
    for (int i = 0; i < 16; ++i) {
        char hex[3];
        std::sprintf(hex, "%02x", output[i]);
        md5Hash += hex;
    }
    return md5Hash;
}

// 将字符串编码为十六进制表示
std::string stringToHex(const std::string& input) {
    std::ostringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    
    for (char c : input) {
        hexStream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
    }
    
    return hexStream.str();
}

// 将十六进制表示解码为字符串
std::string hexToString(const std::string& hexInput) {
    std::string result;
    
    for (size_t i = 0; i < hexInput.length(); i += 2) {
        std::string byteString = hexInput.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
        result += byte;
    }
    
    return result;
}
// ............................... Generate Update Request(flag 1) ............................... //
std::string gen_update_request_string(ae_ctx *ctx, std::string op, std::string w, std::string ind)
{
    try
    {
        ALIGN(16) int c1, c2;
        if (key_to_blockID.find(w) == key_to_blockID.end()) //|| wc_map[w][0] == 0
        {
            if (op == "0")
            {
                host_print_char("the keyword has not added and can't be deleted!");
                host_print_char(w.c_str());
                exit(1);
            }
            else
            {   
                KeyData w_map;
                w_map.key = w.c_str();
                w_map.c1 = 0;
                w_map.c2 = 0;
                set_wc_map_for_w(w_map);
                KeyData s_w = search_key_in_oram(w);
                c1 = s_w.c1;
                c2 = s_w.c2;
            }
        }
        else
        {   
            KeyData s_w = search_key_in_oram(w);
            c1 = s_w.c1;
            c2 = s_w.c2;
        }

        std::string sw, st, s1;
        std::string l, e, proof;
        e_ctx *fctx1 = e_allocate(NULL);
        e_init(fctx1, k_s, 16);
        ALIGN(16) const char *cw = w.c_str();
        ALIGN(16) char csw[16];
        fencrypt1(fctx1, iv_s, cw, w.length(), csw);
        sw.assign(csw, 16);
        ALIGN(16) unsigned long ae_ind;
        ALIGN(16) unsigned long ae_tag;
        std::string opind = op + ind;
        ALIGN(16) const char *indp = opind.c_str();
        e_ctx *fctx2 = e_allocate(NULL);
        e_init(fctx2, k_t, 16);
        std::string wc1c2;
        ALIGN(16) const char *cwc1c2;
        ALIGN(16) char cst[16];
        if (c1 == 0)
        {   
            c1 = 1;
            wc1c2 = w + std::to_string(c1) + std::to_string(c2);
            cwc1c2 = wc1c2.c_str();
            fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
            st.assign(cst, 16);
            e = Util::Xor("0000000000000000" + opind, Util::H2(sw + st));
            ae_encrypt(ctx, &c1, indp, 8, &ae_ind, &ae_tag);
            proof = std::to_string(ae_ind) + "|" + std::to_string(ae_tag) + "|";
        }
        else
        {   
            wc1c2 = w + std::to_string(c1) + std::to_string(c2);
            cwc1c2 = wc1c2.c_str();
            fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
            s1.assign(cst, 16);
            c1 += 1;
            wc1c2 = w + std::to_string(c1) + std::to_string(c2);
            cwc1c2 = wc1c2.c_str();
            fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
            st.assign(cst, 16);
            e = Util::Xor(s1 + opind, Util::H2(sw + st));
            ae_encrypt(ctx, &c1, indp, 8, &ae_ind, &ae_tag);
            proof = std::to_string(ae_ind) + "|" + std::to_string(ae_tag) + "|";
        }
        l = Util::H1(sw + st);
        set_c1c2(w, c1, c2);
        e_clear(fctx1);
        e_free(fctx1);
        e_clear(fctx2);
        e_free(fctx2);
        // host_print_char(" ------------------------ All done in generate update strings ------------------------ ");
        // std::string md5sw = calculateMD5(sw.c_str());
        // std::string md5st = calculateMD5(st.c_str());
        // std::string md5l = calculateMD5(l.c_str());
        // std::string md5e = calculateMD5(e.c_str());
        // std::string md5proof = calculateMD5(proof.c_str());
        host_print_char(w.c_str());
        host_print_char(proof.c_str());
        host_print_int(c1);
        // host_print_char(md5sw.c_str());
        // host_print_char(md5st.c_str());
        // host_print_char(md5l.c_str());
        // host_print_char(md5e.c_str());
        // host_print_char(md5proof.c_str());
        std::string res = stringToHex(l) + "|"+ stringToHex(e) +"|" + stringToHex(proof);
        return res;
    }
    catch (const std::exception &e)
    {
        host_print_char("gen_update_request failed!!!!!");
        exit(1);
    }
}


// std::vector<DataElement> updates(std::vector<StringPair> pairs)
std::string updates(std::vector<StringPair> pairs)
{
    // host_print_char(" ------------------------ Start in updates ------------------------ ");
    std::vector<DataElement> data_vector;
    std::string res;
    data_vector.reserve(pairs.size());
    std::string keyword;
    std::string ind;
    std::string last = " ";
    ae_ctx *ctx = ae_allocate(NULL);
    e_ctx *fctx = e_allocate(NULL);
    e_init(fctx, k_p, 16);
    int c2;
    std::string wc2;
    ALIGN(16) const char *cwc2;
    ALIGN(16) char pw[16];
    for (int i = 0; i < pairs.size(); i++)
    {
        StringPair p = pairs.at(i);
        keyword = std::string(p.key);
        ind = std::string(p.value);
        if (last != keyword)
        {   
            c2 = get_c2(keyword);
            wc2 = keyword + std::to_string(c2);
            cwc2 = wc2.c_str();
            fencrypt1(fctx, iv_s, cwc2, wc2.length(), pw);
            ae_init(ctx, (unsigned char *)pw, 16);
        }
        // UpdateRequest ret = gen_update_request_string(ctx, "1", keyword, ind);
        std::string ret = gen_update_request_string(ctx, "1", keyword, ind);
        res += (ret + "\n");
        last = keyword;
    }
    ae_clear(ctx);
    ae_free(ctx);
    e_clear(fctx);
    e_free(fctx);
    // host_print_char(res.c_str());
    // host_print_char(" ------------------------ All done in updates ------------------------- ");
    return res;
}

// ............................... Generate Synthetic Update(flag 2) ............................... //
// std::vector<DataElement> synthetic_updates(int n)
// {
//     // host_print_char(" ------------------------ Start in synthetic_updates ------------------------ ");
//     int i, j;
//     std::string keyword, ind;
//     int id;
//     std::vector<DataElement> data_vector;
//     ae_ctx *ctx = ae_allocate(NULL);
//     int c2;
//     e_ctx *fctx = e_allocate(NULL);
//     e_init(fctx, (unsigned char *)k_p, 16);
//     std::string wc2;
//     ALIGN(16)
//     const char *cwc2;
//     ALIGN(16)
//     char key[16];
//     host_print_char("generate 79/200 * n keywords, every keyword matches a document");
//     // generate 79/200 * n keywords, every keyword matches a document
//     for (i = 0; i < n * 79 / 200; i++)
//     {
//         keyword = "0keyword" + std::to_string(i);
//         id = rand() % 8999999;
//         ind = std::to_string(1000000 + id);
//         c2 = get_c2(keyword);
//         wc2 = keyword + std::to_string(c2);
//         cwc2 = wc2.c_str();
//         fencrypt1(fctx, iv_s, (const unsigned char *)cwc2, wc2.length(), key);
//         ae_init(ctx, (unsigned char *)key, 16);
//         UpdateRequest ret = gen_update_request_string(ctx, "1", keyword, ind);
//         DataElement element;
//         memcpy(element.l, ret.l.data(), SIZE_L);
//         memcpy(element.e, ret.e.data(), SIZE_E);
//         memcpy(element.proof, ret.proof.data(), SIZE_PROOF);
//         data_vector.push_back(element);
//     }
//     host_print_char("generate 1/2 * n keywords，every keyword macthes 10 documents");
//     // generate 1/2 * n keywords，every keyword macthes 10 documents
//     for (i = 0; i < n / 2; i++)
//     {
//         keyword = "1keyword" + std::to_string(i);
//         c2 = get_c2(keyword);
//         wc2 = keyword + std::to_string(c2);
//         cwc2 = wc2.c_str();
//         fencrypt1(fctx, iv_s, (const unsigned char *)cwc2, wc2.length(), key);
//         ae_init(ctx, (unsigned char *)key, 16);
//         for (j = 0; j < 10; j++)
//         {
//             id = rand() % 8999999;
//             ind = std::to_string(1000000 + id);
//             UpdateRequest ret = gen_update_request_string(ctx, "1", keyword, ind);
//             DataElement element;
//             memcpy(element.l, ret.l.data(), SIZE_L);
//             memcpy(element.e, ret.e.data(), SIZE_E);
//             memcpy(element.proof, ret.proof.data(), SIZE_PROOF);
//             data_vector.push_back(element);
//         }
//     }
//     // generate 1/10 *n keywords， every keyword matches 100 docuemnts
//     host_print_char("generate 1/10 *n keywords， every keyword matches 100 docuemnts");
//     for (i = 0; i < n / 10; i++)
//     {
//         keyword = "2keyword" + std::to_string(i);
//         c2 = get_c2(keyword);
//         wc2 = keyword + std::to_string(c2);
//         cwc2 = wc2.c_str();
//         fencrypt1(fctx, iv_s, (const unsigned char *)cwc2, wc2.length(), key);
//         ae_init(ctx, (unsigned char *)key, 16);
//         for (j = 0; j < 100; j++)
//         {
//             id = rand() % 8999999;
//             ind = std::to_string(1000000 + id);
//             UpdateRequest ret = gen_update_request_string(ctx, "1", keyword, ind);
//             DataElement element;
//             memcpy(element.l, ret.l.data(), SIZE_L);
//             memcpy(element.e, ret.e.data(), SIZE_E);
//             memcpy(element.proof, ret.proof.data(), SIZE_PROOF);
//             data_vector.push_back(element);
//         }
//     }
//     // generate 1/200 *n keywords， every keyword macthes 1000 documents
//     host_print_char("generate 1/200 *n keywords， every keyword macthes 1000 documents");
//     for (i = 0; i < n / 200; i++)
//     {
//         keyword = "3keyword" + std::to_string(i);
//         c2 = get_c2(keyword);
//         wc2 = keyword + std::to_string(c2);
//         cwc2 = wc2.c_str();
//         fencrypt1(fctx, iv_s, (const unsigned char *)cwc2, wc2.length(), key);
//         ae_init(ctx, (unsigned char *)key, 16);
//         for (j = 0; j < 1000; j++)
//         {
//             id = rand() % 8999999;
//             ind = std::to_string(1000000 + id);
//             UpdateRequest ret = gen_update_request_string(ctx, "1", keyword, ind);
//             DataElement element;
//             memcpy(element.l, ret.l.data(), SIZE_L);
//             memcpy(element.e, ret.e.data(), SIZE_E);
//             memcpy(element.proof, ret.proof.data(), SIZE_PROOF);
//             data_vector.push_back(element);
//         }
//     }
//     ae_clear(ctx);
//     ae_free(ctx);
//     e_clear(fctx);
//     e_free(fctx);
//     // host_print_char(" ------------------------ synthetic_updates complete ------------------------ ");
//     return data_vector;
// }

// ............................... Search & Renew(flag 3) ............................... //
bool verify(const std::string w, const std::string st, std::unordered_set<std::string> result, std::vector<std::string> proofs, int c1, int c2)
{   
    // host_print_char(" ------------------------ Verify ------------------------ ");
    std::unordered_set<std::string>::iterator it;
    e_ctx *fctx = e_allocate(NULL);
    e_init(fctx, k_p, 16);
    std::string wc2 = w + std::to_string(c2);
    ALIGN(16) const char *cwc2 = wc2.c_str();
    ALIGN(16) char key[16];
    fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
    ae_ctx *ctx = ae_allocate(NULL);
    ae_init(ctx, (unsigned char *)key, 16);
    std::string item;
    int c_ind = 1;
    int i = 0;
    char *cs = const_cast<char *>(proofs[c1 - 1].c_str());
    const char *d = "|";
    char *p;
    if (c2 > 0)
    {
        p = strtok(cs, d);
        c_ind = atoi(p);
    }
    ALIGN(16) unsigned long ae_inds[c_ind + 1];
    ALIGN(16) unsigned long ae_tag;
    if (c2 > 0)
    {
        p = strtok(NULL, d);
        while (p)
        {
            ae_inds[i++] = strtoul(p, NULL, 10);
            p = strtok(NULL, d);
        }
    }
    else
    {
        p = strtok(cs, d);;
        while (p)
        {
            ae_inds[i++] = strtoul(p, NULL, 10);
            p = strtok(NULL, d);
        }
    }
    int c_inds_bytes = c_ind * 8;
    ALIGN(16) char *inds = new char[c_inds_bytes];
    ALIGN(16) int nonce = 1;
    ae_decrypt(ctx, &nonce, ae_inds, c_inds_bytes, inds, &ae_inds[c_ind]);
    std::unordered_set<std::string> result2;
    char *pos = inds;
    std::string s_ind, op;
    for (i = 0; i < c_ind; i++)
    {
        s_ind = std::string(pos + 1, pos + 8);
        result2.insert(s_ind);
        pos += 8;
    }
    ALIGN(16) unsigned long ae_ind;
    ALIGN(16) char ind[8];
    int j;
    for (i = c1 - 2; i >= 0; i--)
    {
        nonce += 1;
        cs = const_cast<char *>(proofs[i].c_str());
        p = strtok(cs, d);
        ae_ind = strtoul(p, NULL, 10);
        // std::getline(ss, item, '|');
        p = strtok(NULL, d);
        ae_tag = strtoul(p, NULL, 10);
        ae_decrypt(ctx, &nonce, &ae_ind, 8, ind, &ae_tag);
        op = std::string(ind, ind + 1);
        s_ind = std::string(ind + 1, ind + 8);
        host_print_char(s_ind.c_str());
        if (op == "1")
        {
            result2.insert(s_ind);
        }
        else
        {
            it = result2.find(s_ind);
            if (it != result2.end())
            {
                result2.erase(s_ind);
            }
        }
    }
    if (result == result2)
    {   
        host_print_char("Verify equal, ACCEPT");
        ae_clear(ctx);
        ae_free(ctx);
        e_clear(fctx);
        e_free(fctx);
        return 1;
    }
    else
    {
        host_print_char("Verify NOT Equal, REJECT");
        ae_clear(ctx);
        ae_free(ctx);
        return 0;
    }
    // host_print_char(" ------------------------ Verify complete ------------------------ ");
    return 1;
}

int search_renew(std::string w)
{
    // host_print_char(" ------------------------ Starting in Search Renew ------------------------ ");
    std::string mes = "client search: " + w;
    host_print_char(mes.c_str());
    ALIGN(16) int c1, c2;
    if (key_to_blockID.find(w) == key_to_blockID.end())
    {
        std::string mes = "the keyword " + w + " does no exist";
        host_print_char(mes.c_str());
        return 0;
    }
    KeyData s_w = search_key_in_oram(w);
    c1 = s_w.c1;
    c2 = s_w.c2;
    std::string sw, st;
    e_ctx *fctx1 = e_allocate(NULL);
    e_init(fctx1, k_s, 16);
    ALIGN(16) const char *cw = w.c_str();
    ALIGN(16) char csw[16];
    fencrypt1(fctx1, iv_s, cw, w.length(), csw);
    sw.assign(csw, 16); 
    bool first = 0;
    if (c2 == 0)
    {
        first = 1;
    }
    e_ctx *fctx2 = e_allocate(NULL);
    e_init(fctx2, k_t, 16);
    std::string wc1c2;
    ALIGN(16) const char *cwc1c2;
    ALIGN(16) char cst[16];
    wc1c2 = w + std::to_string(c1) + std::to_string(c2);
    cwc1c2 = wc1c2.c_str();
    fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
    st.assign(cst, 16);
    std::string l;
    std::string swt = sw + st;
    l = Util::H1(sw + st);

    // std::string md5sw = calculateMD5(sw.c_str());
    // std::string md5st = calculateMD5(st.c_str());
    // std::string md5l = calculateMD5(l.c_str());
    // host_print_char(md5sw.c_str());
    // host_print_char(md5st.c_str());
    // host_print_char(md5l.c_str());

    std::string params = stringToHex(sw) + "|" +
                      stringToHex(st) + "|" +
                      stringToHex(std::to_string(c1)) + "|" +
                      stringToHex(std::to_string(first)) + "|" +
                      stringToHex(l);

    // SearchParameters params;
    // memcpy(params.sw, sw.data(), 16);
    // memcpy(params.st, st.data(), 16);
    // params.c1 = c1;
    // params.first = first;
    // memcpy(params.l, l.data(), 32);
    SearchResult searchResult;
    oe_result_t result_oe = search_server(&searchResult, params.c_str());

    std::string result_str(searchResult.result);
    std::string proofs_str(searchResult.proofs);

    std::unordered_set<std::string> result;
    std::istringstream result_stream(result_str);
    std::string token;
    while (std::getline(result_stream, token, ',')) {
        result.insert(token);
    }
    std::vector<std::string> proofs;
    std::istringstream proofs_stream(proofs_str);
    while (std::getline(proofs_stream, token, ',')) {
        proofs.push_back(token);
    }

    bool r = verify(w, st, result, proofs, c1, c2); 
    if (!r)
    {
        return 0;
    } 
    if (result.size() < c1)
    {   
        std::string mes11 = "c1: " + std::to_string(c1) + " result size:" + std::to_string(result.size());
        host_print_char(mes11.c_str());
        host_print_char("Need Reproof, starting reproof function...");
        // double start = FT_VDSSE::Util::getCurrentTime();
        c1 = 1;
        c2 += 1;
        set_c1c2(w, c1, c2);        
        e_ctx *fctx = e_allocate(NULL);
        e_init(fctx, k_p, 16);
        std::string wc2 = w + std::to_string(c2);
        ALIGN(16) const unsigned char *cwc2 = reinterpret_cast<const unsigned char *>(wc2.c_str());
        ALIGN(16) char key[16];
        fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
        ae_ctx *ctx = ae_allocate(NULL);
        ae_init(ctx, key, 16);
        e_ctx *fctx2 = e_allocate(NULL);
        e_init(fctx2, k_t, 16);
        std::string wc1c2;
        ALIGN(16) const unsigned char *cwc1c2;
        ALIGN(16) char cst[16];
        wc1c2 = w + std::to_string(c1) + std::to_string(c2);
        cwc1c2 = reinterpret_cast<const unsigned char *>(wc1c2.c_str());
        fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
        st.assign(cst, 16);
        std::unordered_set<std::string>::iterator it;
        std::string inds = "";
        for (it = result.begin(); it != result.end(); it++)
        {
            inds += "1" + *it;
        }
        const unsigned char *k_st = (const unsigned char *)st.c_str();
        std ::string enc_inds = ctrencrypt(k_st, iv_s, inds); //!!!!!!!!!!!!!!
        int inds_size = inds.length();
        int inds_bytes = inds_size / 8;
        ALIGN(16) const char *indsp = inds.c_str();
        int k;
        ALIGN(16) unsigned long c_inds[inds_bytes];
        ALIGN(16) unsigned long tag;
        ae_encrypt(ctx, &c1, indsp, inds_size, c_inds, &tag);
        std::string proof = "";
        for (int i = 0; i < inds_bytes; i++)
        {
            proof += std::to_string(c_inds[i]);
            proof += "|";
        }
        proof = proof + std::to_string(tag) + "|";
        std::string mes111 = "w: " + w + " c1: " + std::to_string(c1) + " result size:" + std::to_string(result.size());
        host_print_char(mes111.c_str());
        
        std::string l = Util::H1(sw + st);
        std::string res = stringToHex(l) + "|" +
                          stringToHex(enc_inds) + "|" +
                          stringToHex(proof);
        host_print_char(res.c_str());
        // memcpy(ret.l, l.c_str(), SIZE_L);
        // memcpy(ret.e, enc_inds.c_str(), SIZE_E);
        // memcpy(ret.proof, proof.c_str(), SIZE_PROOF);
        ae_clear(ctx);
        ae_free(ctx);
        e_clear(fctx);
        e_free(fctx);
        e_clear(fctx2);
        e_free(fctx2);
        send_renew_to_server(res.c_str());
    }
    // host_print_char(" ------------------------ Search_Renew complete ------------------------ ");
    return result.size();

}

// ............................... Batch Delete(flag 4) ............................... //
std::string del(std::vector<StringPair> pairs)
{
    // host_print_char(" ------------------------ Start in updates ------------------------ ");
    std::vector<DataElement> data_vector;
    std::string res;
    data_vector.reserve(pairs.size());
    std::string keyword;
    std::string ind;
    std::string last = " ";
    ae_ctx *ctx = ae_allocate(NULL);
    e_ctx *fctx = e_allocate(NULL);
    e_init(fctx, k_p, 16);
    int c2;
    std::string wc2;
    ALIGN(16) const char *cwc2;
    ALIGN(16) char key[16];
    for (int i = 0; i < pairs.size(); i++)
    {
        StringPair p = pairs.at(i);
        keyword = std::string(p.key);
        ind = std::string(p.value);
        if (last != keyword){
            c2 = get_c2(keyword);
            wc2 = keyword + std::to_string(c2);
            cwc2 = wc2.c_str();
            fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
            ae_init(ctx, (unsigned char*)key, 16);
        }
        // UpdateRequest ret = gen_update_request_string(ctx, "0", keyword, ind);
        std::string ret = gen_update_request_string(ctx, "0", keyword, ind);
        res += (ret + "\n");
        last = keyword;
        // DataElement element;
        // memcpy(element.l, ret.l.data(), SIZE_L);
        // memcpy(element.e, ret.e.data(), SIZE_E);
        // memcpy(element.proof, ret.proof.data(), SIZE_PROOF);
        // data_vector.push_back(element);
        // last = keyword;
    }
    ae_clear(ctx);
    ae_free(ctx);
    e_clear(fctx);
    e_free(fctx);
    // host_print_char(" ------------------------All done in del ------------------------ ");
    return res;
}

// ............................... Trace Simulation(flag 5) ............................... //
// std::vector<DataElement> updatetest(std::string keyword, std::vector<StringPair> index)
// {
//     // host_print_char(" ------------------------ start updatetest ------------------------- ");
//     std::vector<DataElement> data_vector;
//     data_vector.reserve(index.size());
//     std::string op;
//     std::string ind;
//     ae_ctx *ctx = ae_allocate(NULL);
//     e_ctx *fctx = e_allocate(NULL);
//     e_init(fctx, k_p, 16);
//     int c1, c2;
//     std::string wc2;
//     ALIGN(16)
//     const char *cwc2;
//     std::vector<StringPair> pair;
//     ALIGN(16) char pw[16];
//     if (key_to_blockID.find(keyword) == key_to_blockID.end())
//     {
//         KeyData w_map;
//         w_map.key = keyword.c_str();
//         w_map.c1 = 0;
//         w_map.c2 = 0;
//         set_wc_map_for_w(w_map);
//         c1 = 0;
//         c2 = 0;
//     }
//     else
//     {
//         KeyData s_w = search_key_in_oram(keyword);
//         c1 = s_w.c1;
//         c2 = s_w.c2;
//     }
//     wc2 = keyword + std::to_string(c2);
//     cwc2 = wc2.c_str();
//     fencrypt1(fctx, iv_s, cwc2, wc2.length(), pw);
//     ae_init(ctx, (unsigned char *)pw, 16);
//     for (int i = 0; i < index.size(); i++)
//     {
//         StringPair pair = index.at(i);
//         op = pair.key;
//         ind = pair.value;
//         UpdateRequest request = gen_update_request_string(ctx, op, keyword, ind);
//         if (request.l.length() == 0)
//         {   

//         }
//         else
//         {   
//             DataElement element;
//             memcpy(element.l, request.l.data(), SIZE_L);
//             memcpy(element.e, request.e.data(), SIZE_E);
//             memcpy(element.proof, request.proof.data(), SIZE_PROOF);
//             data_vector.push_back(element);
//         }
//     }
//     ae_clear(ctx);
//     ae_free(ctx);
//     e_clear(fctx);
//     e_free(fctx);
//     send_requests_to_server(data_vector.data(), data_vector.size());
//     // host_print_char(" ------------------------ All done in updatetest ------------------------- ");
//     return data_vector;
// }

// int search(const std::string w, std::unordered_set<std::string> &result, int &c1, int &c2, std::string &sw)
// {
//     // host_print_char(" ------------------------ Starting in Search ------------------------ ");
//     std::string mes = "client search: " + w;
//     host_print_char(mes.c_str());
//     if (key_to_blockID.find(w) == key_to_blockID.end())
//     {
//         std::string mes = "the keyword " + w + " does no exist";
//         host_print_char(mes.c_str());
//         return 0;
//     }
//     KeyData s_w = search_key_in_oram(w);
//     c1 = s_w.c1;
//     c2 = s_w.c2;
//     std::string st;
//     e_ctx *fctx = e_allocate(NULL);
//     e_init(fctx, k_s, 16);
//     ALIGN(16) const char *cw = w.c_str();
//     ALIGN(16) char csw[16];
//     fencrypt1(fctx, iv_s, cw, w.length(), csw);
//     sw.assign(csw, 16);
//     bool first = 0;
//     if (c2 == 0)
//     {
//         first = 1;
//     }
//     e_ctx *fctx2 = e_allocate(NULL);
//     e_init(fctx2, k_t, 16);
//     std::string wc1c2;
//     ALIGN(16) const char *cwc1c2;
//     ALIGN(16) char cst[16];
//     wc1c2 = w + std::to_string(c1) + std::to_string(c2);
//     cwc1c2 = wc1c2.c_str();
//     fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
//     st.assign(cst, 16);
//     std::string l = Util::H1(sw + st);

//     SearchParameters params;
//     memcpy(params.sw, sw.data(), 16);
//     memcpy(params.st, st.data(), 16);
//     params.c1 = c1;
//     params.first = first;
//     memcpy(params.l, l.data(), 32);
//     SearchResult searchResult;
//     oe_result_t result_oe = search_server(&searchResult, &params);

//     std::string result_str(searchResult.result);
//     std::string proofs_str(searchResult.proofs);
//     std::istringstream result_stream(result_str);
//     std::string token;
//     while (std::getline(result_stream, token, ',')) {
//         result.insert(token);
//     }
//     std::vector<std::string> proofs;
//     std::istringstream proofs_stream(proofs_str);
//     while (std::getline(proofs_stream, token, ',')) {
//         proofs.push_back(token);
//     }

//     bool r = verify(w, st, result, proofs, c1, c2); 
//     if (!r)
//     {
//         return 0;
//     }
//     else
//     {
//         return result.size();
//     }
// }

// void renewproof(std::string w, std::unordered_set<std::string> result, int c, std::string sw)
// {
//     // host_print_char(" ------------------------ Start Reproof ------------------------ ");
//     int c1 = 1;
//     int c2 = c + 1;
//     set_c1c2(w, c1, c2);
//     std::string st;
//     e_ctx *fctx = e_allocate(NULL);
//     e_init(fctx, k_p, 16);
//     std::string wc2 = w + std::to_string(c2);
//     ALIGN(16) const unsigned char *cwc2 = reinterpret_cast<const unsigned char *>(wc2.c_str());
//     ALIGN(16) char key[16];
//     fencrypt1(fctx, iv_s, cwc2, wc2.length(), key);
//     ae_ctx *ctx = ae_allocate(NULL);
//     ae_init(ctx, key, 16);
//     e_ctx *fctx2 = e_allocate(NULL);
//     e_init(fctx2, k_t, 16);
//     std::string wc1c2;
//     ALIGN(16) const unsigned char *cwc1c2;
//     ALIGN(16) char cst[16];
//     wc1c2 = w + std::to_string(c1) + std::to_string(c2);
//     cwc1c2 = reinterpret_cast<const unsigned char *>(wc1c2.c_str());
//     fencrypt1(fctx2, iv_t, cwc1c2, wc1c2.length(), cst);
//     st.assign(cst, 16);
//     std::unordered_set<std::string>::iterator it;
//     std::string inds = "";
//     for (it = result.begin(); it != result.end(); it++)
//     {
//         inds += *it;
//     }
//     const unsigned char *k_st = (const unsigned char *)st.c_str();
//     std ::string enc_inds = ctrencrypt(k_st, iv_s, inds);
//     int inds_size = inds.length();
//     int inds_bytes = inds_size / 8;
//     ALIGN(16) const char *indsp = inds.c_str();
//     int k;
//     ALIGN(16) unsigned long c_inds[inds_bytes];
//     ALIGN(16) unsigned long tag;
//     ae_encrypt(ctx, &c1, indsp, inds_size, c_inds, &tag);
//     std::string proof = "";
//     for (int i = 0; i < inds_bytes; i++)
//     {
//         proof += std::to_string(c_inds[i]);
//         proof += "|";
//     }
//     std::string l = Util::H1(sw + st);

//     DataElement ret;
//     memcpy(ret.l, l.c_str(), SIZE_L);
//     memcpy(ret.e, enc_inds.c_str(), SIZE_E);
//     memcpy(ret.proof, proof.c_str(), SIZE_PROOF);
//     ae_clear(ctx);
//     ae_free(ctx);
//     e_clear(fctx);
//     e_free(fctx);
//     e_clear(fctx2);
//     e_free(fctx2);
//     send_renew_to_server(&ret);
//     // host_print_char(" ------------------------ Reproof complete ------------------------ ");
// }

// ............................... Main Logic ............................... //

oe_result_t enclave_process_commands(const char *input, size_t data_length)
{   
    struct timeval start, end, middle, t1, t2;
    gettimeofday(&t1, NULL);
    std::string md5Hash = calculateMD5(input);
    // host_print_char(md5Hash.c_str());
    // host_print_char("main menu start");
    unsigned char c_k[17] = "0123456789abcdef";
    size_t base64_len = strlen(input);
    unsigned char ciphertext[5000];
    size_t ciphertext_len;
    mbedtls_base64_decode(ciphertext, sizeof(ciphertext), &ciphertext_len, (const unsigned char *)input, base64_len);
    std::string plaintext = decrypt_aes_ecb(ciphertext, ciphertext_len, (const unsigned char *)c_k);
    // std::string plaintext = remove_pkcs7_padding(ciphertext, ciphertext_len);
    gettimeofday(&t2, NULL);

    // host_print_char(" ----------- Enclave 解密用时统计 ----------- ");
    double t1_t2 = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1000000.0;
    std::string mess_t1_t2 = "解密用时：" + std::to_string(t1_t2) + " seconds\n";
    host_print_char(mess_t1_t2.c_str());
    // host_print_char(" ----------- Enclave 解密用时统计 ----------- ");

    std::string message = "input_str: " + plaintext;
    host_print_char(message.c_str());

    std::istringstream iss(plaintext);
    //std::istringstream iss(input);
    int flag;
    std::string str;
    std::string concatenatedString;
    bool firstString = true;

    // 解析标志
    if (!(iss >> flag))
    {
        return OE_FAILURE;
    }
    std::vector<std::string> arguments;
    std::string arg;
    while (iss >> arg)
    {
        arguments.push_back(arg);
    }
    size_t totalLength = arguments.size();
    // host_print_int(flag);
    // host_print_char(concatenate_arguments(arguments).c_str());
    // host_print_int(totalLength);
    int searchresult;
    if (flag == 1) // bacth updates 0<= document identifier <= 8999999
    {              // flag:int  arguments[0]: 读取数量 arguments[1]：文件名称
        // host_print_char("进入case 1");
        size_t index_size = stoi(arguments[0]);
        std::string content = std::string(arguments[1]);
        oe_result_t result;
        std::vector<StringPair> pairs;

        readStringPairs(content, pairs);
        // host_print_char("进入updates...");
	    gettimeofday(&start, NULL);
        // std::vector<DataElement> requests = updates(pairs);
        std::string requests = updates(pairs);
        gettimeofday(&middle, NULL);
        // host_print_char("调用OCALL发送请求到服务器");
        // 调用OCALL发送请求到服务器
        send_requests_to_server(requests.c_str());
        gettimeofday(&end, NULL);
        
	    // host_print_char(" ----------- Flag 1 用时统计 ----------- ");
        double st_md = (middle.tv_sec - start.tv_sec) + (middle.tv_usec - start.tv_usec) / 1000000.0;
        double md_ed = (end.tv_sec - middle.tv_sec) + (end.tv_usec - middle.tv_usec) / 1000000.0;
        double st_ed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

        
        std::string mess_st_md = "flag1 - 生成request字符串用时" + std::to_string(st_md) + " seconds\n";
        std::string mess_md_ed = "flag1 - 发送request到服务器用时: " + std::to_string(md_ed) + " seconds\n";
        std::string mess_st_ed = "flag1 - update总用时: " + std::to_string(st_ed) + " seconds\n";

        host_print_char(mess_st_md.c_str());
        host_print_char(mess_md_ed.c_str());
        host_print_char(mess_st_ed.c_str());

	    // host_print_char(" ----------- Flag 1 用时统计 ----------- ");
    }
    else if (flag == 2) // create the synthetic database
    {                   // flag:int  arguments[0]: 参数n
        host_print_char("进入case 2");
        int content = stoi(arguments[0]);
        host_print_char("进入synthetic...");
        // std::vector<DataElement> requests = synthetic_updates(content);
        // send_requests_to_server(requests.data(), requests.size());
    }
    else if (flag == 3) // search + renew proof
    {
        // host_print_char("进入case 3");
        std::string w = std::string(arguments[0]);
        // host_print_char("进入search renew...");
        gettimeofday(&start, NULL);
        searchresult = search_renew(w);
        gettimeofday(&end, NULL);
        if (searchresult > 0){
            host_print_char("search done: ");
        } else {
            host_print_char("search error: ");
        }

        host_print_char(" ----------- Flag 3 用时统计 ----------- ");
        double st_ed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
        std::string mess_st_ed = "flag3 - search用时: " + std::to_string(st_ed) + " seconds\n";
        host_print_char(mess_st_ed.c_str());

    }else if (flag == 4) // batch deletes
    {                   // flag:int  arguments[0]: 文件名称
        // host_print_char("进入case 4");
        std::string content = std::string(arguments[0]);
        oe_result_t result;
        std::vector<StringPair> pairs;

        

        readStringPairs(content, pairs);

        gettimeofday(&start, NULL);
        // host_print_char("进入del...");
        std::string requests = del(pairs);
        // // 调用OCALL发送请求到服务器
        gettimeofday(&middle, NULL);
        send_requests_to_server(requests.c_str());
        
        gettimeofday(&end, NULL);
        // host_print_char(" ----------- Flag 4 用时统计 ----------- ");
        double st_md = (middle.tv_sec - start.tv_sec) + (middle.tv_usec - start.tv_usec) / 1000000.0;
        double md_ed = (end.tv_sec - middle.tv_sec) + (end.tv_usec - middle.tv_usec) / 1000000.0;
        double st_ed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

        std::string mess_st_md = "flag4 - 生成request字符串用时" + std::to_string(st_md) + " seconds\n";
        std::string mess_md_ed = "flag4 - 发送request到服务器用时: " + std::to_string(md_ed) + " seconds\n";
        std::string mess_st_ed = "flag4 - update总用时: " + std::to_string(st_ed) + " seconds\n";

        host_print_char(mess_st_md.c_str());
        host_print_char(mess_md_ed.c_str());
        host_print_char(mess_st_ed.c_str());

	    // host_print_char(" ----------- Flag 1 用时统计 ----------- ");
    }else if (flag == 5)
    {
        host_print_char("进入case 5");
        // std::string content = std::string(arguments[0]);
        // char s1[100];
        // char s2[100];
        // int id;
        // int upds;
        // std::string keyword = "pray22";
        // std::vector<StringPair> updates;
        // std::string function, op, ind;

        // std::vector<StringTriple> pairs;
        // readStringTriple(content, pairs);
        // // char *token;
        // // char *buffer = new char[content.size() + 1];
        // // std::strcpy(buffer, content.c_str());
        // // token = strtok(buffer, ",");
        // // while(token != NULL) {
        // for (int i = 0; i < pairs.size(); i++)
        // {   
        //     int id, upds;
        //     // sscanf(token, "%d|%s|%d", &upds, s2, &id);
        //     StringTriple s = pairs.at(i);
        //     upds = atoi(s.upds);
        //     memcpy(s2, s.s2, sizeof(s2));
        //     id = atoi(s.id);
        //     function  = s2;
        //     if (function == "add"){
        //         // host_print_char("add");
        //         op = "1";
        //         ind = std::to_string(1000000 + id);
        //         StringPair p;
        //         memcpy(p.key, op.c_str(), sizeof(p.key));
        //         memcpy(p.value, ind.c_str(), sizeof(p.value));
        //         updates.push_back(p); 
        //     } else if (function == "del"){
        //         // host_print_char("del");
        //         op = "0";
        //         ind = std::to_string(1000000 + id);
        //         StringPair p;
        //         memcpy(p.key, op.c_str(), sizeof(p.key));
        //         memcpy(p.value, ind.c_str(), sizeof(p.value));
        //         updates.push_back(p); 
        //     } else if (function == "search"){
        //         // host_print_char("search");
        //         std::vector<DataElement> update_request = updatetest(keyword, updates);
        //         send_requests_to_server(update_request.data(), update_request.size());
        //         updates.clear();
        //         std::unordered_set <std::string> result;
        //         int c3, c4;
        //         std::string sw;
        //         // double start = getCurrentTime();
        //         searchresult = search(keyword, result, c3, c4, sw); 
        //         //处理searchresult提取result
        //         // double end = getCurrentTime();
        //         if (searchresult > 0){
        //             // std::string mes_time = std::to_string(upds) + " " + std::to_string((end -start) *1000);
        //             // host_print_char(mes_time.c_str());
        //             host_print_char("search done: ");
        //             if(searchresult < c3){
        //                 renewproof(keyword, result, c4, sw);
        //             }
        //         } else {
        //             host_print_char("search error: ");
        //         }
        //     }else{
        //         std::string final_mes = "当前序号为： " + std::to_string(upds) + " , function: " + function;
        //         host_print_char(final_mes.c_str());
            // }
            
            // token = strtok(NULL, ",");
    // }
    } 

    return OE_OK;
}
