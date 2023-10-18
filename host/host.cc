#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <openenclave/host.h>
#include <stdio.h>
#include "helloworld_u.h"
#include <grpc++/grpc++.h>
#include <grpcpp/security/server_credentials.h>
#include <typeinfo>
#include <cstdio>
#include <unordered_set>
#include <sys/time.h>
#include <time.h>
// #include "../enclave/FT_VDSSE.Util.h"
#include <openssl/md5.h>
// #include "mbedtls/base64.h"


#define SIZE_L 32
#define SIZE_E 50
#define SIZE_PROOF 50

// struct DataElement {
//     char l[100];
//     char e[100];
//     char proof[100];
// };

// typedef struct
// {
//     DataElement elements[1000];
//     size_t size;
// } DataArray;

bool check_simulate_opt(int *argc, const char *argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char *));
            (*argc)--;
            return true;
        }
    }
    return false;
}
std::string md5(const std::string& data) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)data.c_str(), data.size(), (unsigned char*)&digest);

    std::stringstream ss;
    for(int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

    return ss.str();
}

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <openssl/ssl.h>
// #include <openssl/bio.h>
// #include <openssl/evp.h>
// #include <openssl/buffer.h>

// std::string base64Encode(const std::string &input) {
//     BIO *bio, *b64;
//     BUF_MEM *bufferPtr;

//     b64 = BIO_new(BIO_f_base64());
//     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//     bio = BIO_new(BIO_s_mem());
//     BIO_push(b64, bio);
//     BIO_write(b64, input.c_str(), input.length());
//     BIO_flush(b64);
//     BIO_get_mem_ptr(b64, &bufferPtr);
//     std::string result(bufferPtr->data, bufferPtr->length);
//     BIO_free_all(b64);

//     return result;
// }

// std::string base64Decode(const std::string &input) {
//     BIO *bio, *b64;
//     char *outputBuffer = new char[input.length()];
//     int outputLength = 0;

//     b64 = BIO_new(BIO_f_base64());
//     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//     bio = BIO_new_mem_buf(input.c_str(), input.length());
//     bio = BIO_push(b64, bio);
//     outputLength = BIO_read(bio, outputBuffer, input.length());
//     BIO_free_all(b64);

//     return std::string(outputBuffer, outputLength);
// }
// Base64 解码功能
// std::string base64Decode(const std::string &input) {
//     const unsigned char *inputData = reinterpret_cast<const unsigned char *>(input.c_str());
//     size_t inputLength = input.length();

//     unsigned char output[256]; // 适当调整缓冲区大小
//     size_t outputLength = 0;

//     int decodeResult = mbedtls_base64_decode(output, sizeof(output), &outputLength, inputData, inputLength);
//     if (decodeResult == 0) {
//         return std::string((char *)output, outputLength);
//     } else {
//         std::cerr << "Base64 Decoding Error" << std::endl;
//         return "";
//     }
// }

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

/*------------------------------------------------------------------------------*/
#include "FT_VDSSE.grpc.pb.h"
#include "FT_VDSSE.pb.h"
#include <iomanip>

namespace FT_VDSSE
{
    class FT_VDSSEServiceImpl final : public RPC::Service
    {
        oe_enclave_t *enclave;

    public:
        FT_VDSSEServiceImpl(int argc, const char *argv[])
        {
            oe_result_t result;
            //const char *sign = "/home/scui2/xz_thesis/helloworld/build/enclave/enclave.signed";
            uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
            if (check_simulate_opt(&argc, argv))
            {
                flags |= OE_ENCLAVE_FLAG_SIMULATE;
            }
            
            result = oe_create_helloworld_enclave(argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
            if (result != OE_OK)
            {
                throw std::runtime_error("oe_create_helloworld_enclave() failed");
            }
        }

        grpc::Status SendData(grpc::ServerContext *context, const DataRequest *request, DataResponse *response) override
        {   
            struct timeval t1, t2, t3;
            gettimeofday(&t1, NULL);
            // std::cout << "Received: " << request->input_content() << std::endl; // 打印接收到的命令以供调试
            // 将接收到的命令发送到Enclave进行处理
            const char* input_content = request->input_content().c_str();
		    size_t content_size = request->input_content().size();
            // std::cout << "Received: " << request->input_content() << std::endl; // 打印接收到的命令以供调试
            // std::cout << "Size: " << request->input_content().size() << std::endl; // 打印接收到的命令以供调试
            std::cout << "md5: " << md5(input_content) << std::endl; // 打印接收到的命令以供调试
            oe_result_t internal_result;
            gettimeofday(&t2, NULL);
            oe_result_t result = enclave_process_commands(enclave, &internal_result, input_content, content_size);
            gettimeofday(&t3, NULL);
            host_print_char(" ----------- 接收外部数据/发送->enclave 用时统计 ----------- ");
            double t1_t2 = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1000000.0;
            double t3_t2 = (t3.tv_sec - t2.tv_sec) + (t3.tv_usec - t2.tv_usec) / 1000000.0;
            double t3_t1 = (t3.tv_sec - t1.tv_sec) + (t3.tv_usec - t1.tv_usec) / 1000000.0;
            
            std::string mess_t1_t2 = "接收数据用时：" + std::to_string(t1_t2) + " seconds\n";
            std::string mess_t2_t3 = "Enclave处理用时：" + std::to_string(t3_t2) + " seconds\n";
            std::string mess_t3_t1 = "SendData总用时：" + std::to_string(t3_t1) + " seconds\n";
            host_print_char(mess_t1_t2.c_str());
            host_print_char(mess_t2_t3.c_str());
            host_print_char(mess_t3_t1.c_str());

            std::cout << "result: " << oe_result_str(result) << std::endl;

            if (result != OE_OK)
            {
                std::cerr << "Error processing command: " << oe_result_str(result) << std::endl;
                response->set_message(oe_result_str(result));
                return grpc::Status::OK;
            }

            response->set_message("Success "+ std::to_string(t3_t1));
            return grpc::Status::OK;
        }
    };
} // namespace FT_VDSSE

/*------------------------------------------------------------------------------*/

void host_print_char(const char *str)
{
    std::cout << "host print:" << str << std::endl;
}

void host_print_int(int num)
{
    std::cout << "host print:" << num << std::endl;
}

void send_requests_to_server(const char *res)
{
    struct timeval t1, t2, t3;
    gettimeofday(&t1, NULL);
    // std::cout << "batch_update_to_server starting..." << std::endl;
    grpc::ClientContext context;
    FT_VDSSE::ExecuteStatus exec_status;
    std::unique_ptr<FT_VDSSE::RPC::Stub> stub_(FT_VDSSE::RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr<grpc::ClientWriter<FT_VDSSE::UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));
    // std::cout << "-------------------------HOST update request CHECK!!!!!!!------------------------" << std::endl;
    std::vector<std::string> lines;
    std::istringstream iss(res);
    std::string line;
    // 使用换行符分隔字符串，将每一行存储到 vector 中
    while (std::getline(iss, line)) {
        lines.push_back(line);
    }
    gettimeofday(&t2, NULL);
    // 遍历每一行，再次使用分隔符（例如 '|'）将每一行拆分为 l, e, 和 proof
    for (const std::string& row : lines) {
        std::istringstream rowStream(row);
        std::string l, e, proof;
        char delimiter = '|';

        // 将request_str拆分为l、e和proof部分
        if (std::getline(rowStream, l, delimiter) &&
            std::getline(rowStream, e, delimiter) &&
            std::getline(rowStream, proof, delimiter))
        {
            FT_VDSSE::UpdateRequestMessage request;
            // std::cout << "--将request_str转换为UpdateRequestMessage--" << std::endl;
            std::string ldata (hexToString(l).c_str(), 32);
            std::string edata (hexToString(e).c_str(), 24);
            std::string proofdata (hexToString(proof).c_str(), 32);
            request.set_l(ldata);
            request.set_e(edata);
            request.set_proof(proofdata);
            std::string hash_l = md5(ldata);
            std::string hash_e = md5(edata);
            std::string hash_proof = md5(proofdata);
            // std::cout << "e: " << edata << std::endl;
            // std::cout << "proof: " << proofdata << std::endl;
            // std::cout << "md5 hash l: " << hash_l << std::endl;
            // std::cout << "md5 hash e: " << hash_e << std::endl;
            // std::cout << "md5 hash proof: " << hash_proof << std::endl;
            writer->Write(request);
        }
    }
    gettimeofday(&t3, NULL);
    host_print_char(" ----------- send_requests_to_server 用时统计 ----------- ");
    double t1_t2 = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1000000.0;
    double t3_t2 = (t3.tv_sec - t2.tv_sec) + (t3.tv_usec - t2.tv_usec) / 1000000.0;
    double t3_t1 = (t3.tv_sec - t1.tv_sec) + (t3.tv_usec - t1.tv_usec) / 1000000.0;

    std::string mess_t1_t2 = "初始化grpc连接用时：" + std::to_string(t1_t2) + " seconds\n";
    std::string mess_t2_t3 = "生成grpc请求用时：" + std::to_string(t3_t2) + " seconds\n";
    std::string mess_t3_t1 = "update request(grpc部分)总用时：" + std::to_string(t3_t1) + " seconds\n";
    host_print_char(mess_t1_t2.c_str());
    host_print_char(mess_t2_t3.c_str());
    host_print_char(mess_t3_t1.c_str());

    // std::cout << "-------------------------HOST update request CHECK!!!!!!!------------------------" << std::endl;
    // std::cout << "writer completed..." << std::endl;
    writer->WritesDone();
    grpc::Status status = writer->Finish();
    if (!status.ok())
    {
        std::cout << "batch_update error" << std::endl;
    }
}

void send_renew_to_server(const char *res)
{
    struct timeval t1, t2, t3;
    gettimeofday(&t1, NULL);
    grpc::ClientContext context;
    FT_VDSSE::ExecuteStatus exec_status;
    std::unique_ptr<FT_VDSSE::RPC::Stub> stub_(FT_VDSSE::RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
    std::istringstream iss(res);
    // 使用换行符分隔字符串，将每一行存储到 vector 中
    // 遍历每一行，再次使用分隔符（例如 '|'）将每一行拆分为 l, e, 和 proof

    std::string l, e, proof;
    std::vector<std::string> arguments;
    std::string arg;
    while (getline(iss, arg, '|'))
    {
        arguments.push_back(arg);
    }
    size_t totalLength = arguments.size();
    FT_VDSSE::UpdateRequestMessage request;
    // std::cout << "--将request_str转换为UpdateRequestMessage--" << std::endl;
    std::string ldata(hexToString(arguments[0]).c_str(), 32);
    std::string edata(hexToString(arguments[1]).c_str(), 24);
    std::string proofdata(hexToString(arguments[2]).c_str(), 32);
    request.set_l(ldata);
    request.set_e(edata);
    request.set_proof(proofdata);
    gettimeofday(&t2, NULL);

    // std::cout << "-------------------------HOST renew request CHECK!!!!!!!------------------------" << std::endl;
    // std::string hash_l = md5(l);
    // std::string hash_e = md5(e);
    // std::string hash_proof = md5(proof);
    // std::cout << "l: " << l << std::endl;
    // std::cout << "l length: " << ldata.length() << std::endl;
    // std::cout << "e: " << e << std::endl;
    // std::cout << "e length: " << edata.length() << std::endl;
    // std::cout << "proof: " << proofdata << std::endl;
    // std::cout << "proof length: " << proof.length() << std::endl;
    // std::cout << "md5 hash l: " << hash_l << std::endl;
    // std::cout << "md5 hash e: " << hash_e << std::endl;
    // std::cout << "md5 hash proof: " << hash_proof << std::endl;
    // std::cout << "-------------------------HOST renew request CHECK!!!!!!!------------------------" << std::endl;

    grpc::Status status = stub_->update2(&context, request, &exec_status);
    gettimeofday(&t3, NULL);
    host_print_char(" ----------- renew 用时统计 ----------- ");
    double t1_t2 = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1000000.0;
    double t3_t2 = (t3.tv_sec - t2.tv_sec) + (t3.tv_usec - t2.tv_usec) / 1000000.0;
    double t3_t1 = (t3.tv_sec - t1.tv_sec) + (t3.tv_usec - t1.tv_usec) / 1000000.0;

    std::string mess_t1_t2 = "生成renew请求用时：" + std::to_string(t1_t2) + " seconds\n";
    std::string mess_t2_t3 = "renew发送用时：" + std::to_string(t3_t2) + " seconds\n";
    std::string mess_t3_t1 = "renew总用时：" + std::to_string(t3_t1) + " seconds\n";
    host_print_char(mess_t1_t2.c_str());
    host_print_char(mess_t2_t3.c_str());
    host_print_char(mess_t3_t1.c_str());
    if (!status.ok())
    {
        std::cout << "renew error" << std::endl;
    }
}
// search request
SearchResult search_server(const char *params)
{   
    // std::cout << "host search_server starting..." << std::endl;
    FT_VDSSE::SearchRequestMessage request;
    grpc::ClientContext context;

    std::istringstream iss(params);
    std::string sw, st, c1, first, l;

    // 使用getline分割字符串
    std::getline(iss, sw, '|');
    std::getline(iss, st, '|');
    std::getline(iss, c1, '|');
    std::getline(iss, first, '|');
    std::getline(iss, l, '|');

    std::string swdata (hexToString(sw).c_str(), 16);
    std::string stdata (hexToString(st).c_str(), 16);
    std::string ldata (hexToString(l).c_str(), 32);
    int c1data = std::stoi(hexToString(c1));
    bool firstdata = (hexToString(first) == "1");
    
    // std::cout << "-------------------------HOST search CHECK!!!!!!!------------------------" << std::endl;
    std::string hash_sw = md5(swdata);
    std::string hash_st = md5(stdata);
    std::string hash_l = md5(ldata);
    // std::cout << "c1: " << c1data << std::endl;
    // std::cout << "first: " << firstdata << std::endl;
    // std::cout << "l: " << l << std::endl;
    // std::cout << "sw length(原): " << hexToString(sw).length() << std::endl;
    // // std::cout << "sw length: " << std::strlen(swdata) << std::endl;
    // std::cout << "sw length: " << swdata.length() << std::endl;
    // std::cout << "st length: " << stdata.length() << std::endl;
    // // std::cout << "st length: " << std::strlen(stdata) << std::endl;
    // std::cout << "md5 hash sw: " << hash_sw << std::endl;
    // std::cout << "md5 hash st: " << hash_st << std::endl;
    // std::cout << "md5 hash l: " << hash_l << std::endl;
    // std::cout << "-------------------------HOST search CHECK!!!!!!!------------------------" << std::endl;

    request.set_sw(swdata);
    request.set_st(stdata);
    request.set_c1(c1data);
    request.set_first(firstdata);

    std::unique_ptr<FT_VDSSE::RPC::Stub> stub_(FT_VDSSE::RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr<grpc::ClientReaderInterface<FT_VDSSE::SearchReply>>  reader = stub_->search(&context, request);
    std::cout << "Got Search Reply..." << std::endl;

    int counter = 0;
    FT_VDSSE::SearchReply reply;
    std::string ind;

    std::string result_str;
    std::string proofs_str;
    
    while (reader->Read(&reply))
    {   
        ind = reply.ind();
        // std::cout << "ind: " << ind << std::endl;
        if (ind != "")
        {
            if (!result_str.empty()) {
                result_str += ",";
            }
            result_str += reply.ind();

        }
        else
        {
            break;
        }
    }
    proofs_str = reply.proof();
    // std::cout << "proof: " << proofs_str << std::endl;
    while (reader->Read(&reply))
    {
        if (!proofs_str.empty()) {
            proofs_str += ",";
        }
        proofs_str += reply.proof();
        // std::cout << "proof: " << reply.proof() << std::endl;
        // searchResult.proofs.push_back(reply.proof());
    }
    SearchResult searchResult;
    std::cout << "results: " << result_str << std::endl;
    std::cout << "proofs : " << proofs_str << std::endl;
    strncpy(searchResult.result, result_str.c_str(), sizeof(searchResult.result));
    strncpy(searchResult.proofs, proofs_str.c_str(), sizeof(searchResult.proofs));
    return searchResult;
}


int main(int argc, const char *argv[])
{
    FT_VDSSE::FT_VDSSEServiceImpl service(argc, argv);
    grpc::ServerBuilder builder;
    builder.AddListeningPort("0.0.0.0:50053", grpc::InsecureServerCredentials());
    builder.SetMaxMessageSize(INT_MAX);
    builder.SetMaxReceiveMessageSize(INT_MAX);
    builder.SetMaxSendMessageSize(INT_MAX);

    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    std::cout << "Server listening on port 50053..." << std::endl;
    server->Wait();

    return 0;
}
