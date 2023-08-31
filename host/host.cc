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
// #include "../enclave/FT_VDSSE.Util.h"
#include <openssl/md5.h>


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

// using grpc::Channel;
// using grpc::ClientContext;
// using grpc::ClientReaderInterface;
// using grpc::ClientWriterInterface;
// using grpc::ClientAsyncResponseReaderInterface;
// using grpc::Status;

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
            const char *sign = "/home/lgh/Documents/helloworld/build/enclave/enclave.signed";
            uint32_t flags = OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE;
            result = oe_create_helloworld_enclave(sign, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
            if (result != OE_OK)
            {
                throw std::runtime_error("oe_create_helloworld_enclave() failed");
            }
        }

        grpc::Status SendData(grpc::ServerContext *context, const DataRequest *request, DataResponse *response) override
        {
            std::cout << "Received: " << request->input_content() << std::endl; // 打印接收到的命令以供调试
            // 将接收到的命令发送到Enclave进行处理
            size_t content_size = request->input_content().size();
            std::cout << "Received: " << request->input_content() << std::endl; // 打印接收到的命令以供调试
            std::cout << "Size: " << request->input_content().size() << std::endl; // 打印接收到的命令以供调试
            std::cout << "md5: " << md5(input_content) << std::endl; // 打印接收到的命令以供调试
            oe_result_t internal_result;
            oe_result_t result = enclave_process_commands(enclave, &internal_result, input_content, content_size);

            std::cout << "result: " << oe_result_str(result) << std::endl;

            if (result != OE_OK)
            {
                std::cerr << "Error processing command: " << oe_result_str(result) << std::endl;
                response->set_message(oe_result_str(result));
                return grpc::Status::OK;
            }

            response->set_message("Success");
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



// update request
void send_requests_to_server(DataElement *requests, size_t in_size)
{
    // std::cout << "batch_update_to_server starting..." << std::endl;
    grpc::ClientContext context;
    FT_VDSSE::ExecuteStatus exec_status;
    std::unique_ptr<FT_VDSSE::RPC::Stub> stub_(FT_VDSSE::RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));
    std::unique_ptr<grpc::ClientWriter<FT_VDSSE::UpdateRequestMessage>> writer(stub_->batch_update(&context, &exec_status));

    for (size_t i = 0; i < in_size; ++i)
    {

        FT_VDSSE::UpdateRequestMessage request;
        // 将request_str拆分为l、e和proof部分
        std::string l(requests[i].l, 32);
        std::string e = requests[i].e;
        std::string proof = requests[i].proof;
        //  将request_str转换为UpdateRequestMessage
        request.set_l(l);
        request.set_e(e);
        request.set_proof(proof);
        
        // std::cout << "-------------------------HOST update request CHECK!!!!!!!------------------------" << std::endl;
        // std::string hash_l = md5(l);
        // std::string hash_e = md5(e);
        // std::string hash_proof = md5(proof);
        // std::cout << "l: " << l << std::endl;
        // std::cout << "l length: " << l.length() << std::endl;
        // std::cout << "e: " << e << std::endl;
        // std::cout << "e length: " << e.length() << std::endl;
        // std::cout << "proof: " << proof << std::endl;
        // std::cout << "proof length: " << proof.length() << std::endl;
        // std::cout << "md5 hash l: " << hash_l << std::endl;
        // std::cout << "md5 hash e: " << hash_e << std::endl;
        // std::cout << "md5 hash proof: " << hash_proof << std::endl;
        // std::cout << "-------------------------HOST update request CHECK!!!!!!!------------------------" << std::endl;
       
        writer->Write(request);
    }
    // std::cout << "writer completed..." << std::endl;
    writer->WritesDone();
    grpc::Status status = writer->Finish();
    if (!status.ok())
    {
        std::cout << "batch_update error" << std::endl;
    }
}

void send_renew_to_server(DataElement *requests)
{
    std::cout << "send_renew_to_server starting..." << std::endl;
    grpc::ClientContext context;

    FT_VDSSE::UpdateRequestMessage request;
    FT_VDSSE::ExecuteStatus exec_status;
    std::unique_ptr<FT_VDSSE::RPC::Stub> stub_(FT_VDSSE::RPC::NewStub(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials())));

    // 将request_str拆分为l、e和proof部分
    std::string l(requests->l, 32);
    std::string e = requests->e;
    std::string proof = requests->proof;
    //  将request_str转换为UpdateRequestMessage
    request.set_l(l);
    request.set_e(e);
    request.set_proof(proof);

    // std::cout << "-------------------------HOST renew request CHECK!!!!!!!------------------------" << std::endl;
    // std::string hash_l = md5(l);
    // std::string hash_e = md5(e);
    // std::string hash_proof = md5(proof);
    // std::cout << "l: " << l << std::endl;
    // std::cout << "l length: " << l.length() << std::endl;
    // std::cout << "e: " << e << std::endl;
    // std::cout << "e length: " << e.length() << std::endl;
    // std::cout << "proof: " << proof << std::endl;
    // std::cout << "proof length: " << proof.length() << std::endl;
    // std::cout << "md5 hash l: " << hash_l << std::endl;
    // std::cout << "md5 hash e: " << hash_e << std::endl;
    // std::cout << "md5 hash proof: " << hash_proof << std::endl;
    // std::cout << "-------------------------HOST renew request CHECK!!!!!!!------------------------" << std::endl;

    grpc::Status status = stub_->update2(&context, request, &exec_status);
    if (!status.ok())
    {
        std::cout << "renew error" << std::endl;
    }
}
// search request
// const std::string sw, const std::string st, const int c1, const bool first, std::vector <std::string> &proofs
SearchResult search_server(SearchParameters *params)
{   
    // std::cout << "host search_server starting..." << std::endl;
    FT_VDSSE::SearchRequestMessage request;
    grpc::ClientContext context;

    std::string sw (params->sw, 16);
    std::string st (params->st, 16);
    std::string swt = sw + st;
    int c1 = params->c1;
    bool first = params->first;

    std::string l (params->l, 32);
    
    // std::cout << "-------------------------HOST search CHECK!!!!!!!------------------------" << std::endl;
    // std::string hash_sw = md5(sw);
    // std::string hash_st = md5(st);
    // std::string hash_swt = md5(swt);
    // std::string hash_l = md5(l);
    // std::cout << "sw: " << sw << std::endl;
    // std::cout << "sw length: " << sw.length() << std::endl;
    // std::cout << "st: " << st << std::endl;
    // std::cout << "st length: " << st.length() << std::endl;
    // std::cout << "swt: " << swt << std::endl;
    // std::cout << "swt length: " << swt.length() << std::endl;
    // std::cout << "c1: " << c1 << std::endl;
    // std::cout << "first: " << first << std::endl;
    // std::cout << "l: " << l << std::endl;
    // std::cout << "l length: " << l.length() << std::endl;
    // std::cout << "md5 hash sw: " << hash_sw << std::endl;
    // std::cout << "md5 hash st: " << hash_st << std::endl;
    // std::cout << "md5 hash swt: " << hash_swt << std::endl;
    // std::cout << "md5 hash l: " << hash_l << std::endl;
    // std::cout << "-------------------------HOST search CHECK!!!!!!!------------------------" << std::endl;

    request.set_sw(sw);
    request.set_st(st);
    request.set_c1(c1);
    request.set_first(first);

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
        // std::cout << "ind: " << reply.ind() << std::endl;
        ind = reply.ind();
        if (ind != "")
        {
            if (!result_str.empty()) {
                result_str += ",";
            }
            result_str += reply.ind();
            
            // searchResult.result.insert(reply.ind());
            // strncpy(result[result_counter].ind, reply.ind().c_str(), 1000);
            // result_counter++;
        }
        else
        {
            break;
        }
    }
    // std::cout << "proof: " <<  reply.proof()<< std::endl;
    proofs_str = reply.proof();
    while (reader->Read(&reply))
    {
        if (!proofs_str.empty()) {
            proofs_str += ",";
        }
        proofs_str += reply.proof();
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
    builder.AddListeningPort("0.0.0.0:50052", grpc::InsecureServerCredentials());
    builder.SetMaxMessageSize(INT_MAX);
    builder.SetMaxReceiveMessageSize(INT_MAX);
    builder.SetMaxSendMessageSize(INT_MAX);

    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    std::cout << "Server listening on port 50052..." << std::endl;
    server->Wait();

    return 0;
}
