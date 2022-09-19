
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/data_type.h"
#include "Server.h"
#include "Client.h"
#include "Utils.h"

//for measurement
#include <cstdint>
#include <chrono>
#include <iostream>
uint64_t timeSinceEpochMillisec() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
//end for measurement


#define ENCLAVE_FILE "CryptoEnclave.signed.so"

int total_file_no = (int)100000;//50000;//100000
int total_pair_no = (int)600000;//50000;//100000
int del_no = (int)0;//10000;//10000;

/* 	Note 1: Enclave only recognises direct pointer with count*size, where count is the number of elements in the array, and size is the size of each element
		other further pointers of pointers should have fixed max length of array to eliminate ambiguity to Enclave (by using pointer [max_buf]).
	Note 2: In outcall, passing pointer [out] can only be modified/changed in the direct .cpp class declaring the ocall function.
	Note 3: If it is an int pointer pointing to a number-> using size=sizeof(int) to declare the size of the int pointer. That will be a larger range than using size_t in ocall
	Note 4: ensure when using openssl and sgxcrypto, plaintext data should be more lengthy than 4-5 characters; (each content in raw_doc should have lengthy characters)
			otherwise, random noise/padding will be auto added.
	Note 5: convert to int or length needs to total_filecome with pre-define length;otherwise, following random bytes can occur.

	memory leak note: 
	1-declare all temp variable outside forloop
	2-all func should return void, pass pointer to callee; caller should init mem and free pointer
	3-use const as input parameter in funcs if any variable is not changed 
	4-re-view both client/server in outside regarding above leak,
		 (docContent fetch_data = myClient->ReadNextDoc();, 

			//free memory 
			free(fetch_data.content);
			free(fetch_data.id.doc_id);)
	5-struct should use constructor and destructor (later)
	6-should use tool to check mem valgrind --leak-check=yes to test add function to see whether memory usage/leak before and after
	7-run with prerelease mode
	8-re generate new list test, but without using the list inside
 */

Client *myClient; //extern to separate ocall
Server *myServer; //extern to separate ocall

void ocall_print_string(const char *str) {
    printf("%s\n", str);
}

//server接受enclave传来的T1,T2
void ocall_transfer_encrypted_entries(const void *_t1_u_arr,
									  const void *_t1_v_arr, 
									  const void *_t2_u_arr,
									  const void *_t2_v_arr,
									  int pair_count, int rand_size){

	myServer->ReceiveTransactions(
								(rand_t *)_t1_u_arr,(rand_t *)_t1_v_arr,
								(rand_t *)_t2_u_arr,(rand_t *)_t2_v_arr,
								pair_count);

}

void ocall_retrieve_encrypted_doc(const char *del_id, size_t del_id_len, 
                                  unsigned char *encrypted_content, size_t maxLen,
                                  int *length_content, size_t int_size){
								  
	std::string del_id_str(del_id,del_id_len);	
	std::string encrypted_entry = myServer->Retrieve_Encrypted_Doc(del_id_str);
	
    *length_content = (int)encrypted_entry.size();

	//later double check *length_content exceeds maxLen
    memcpy(encrypted_content, (unsigned char*)encrypted_entry.c_str(),encrypted_entry.size());
}

void ocall_del_encrypted_doc(const char *del_id, size_t del_id_len){
	std::string del_id_str(del_id,del_id_len);
	myServer->Del_Encrypted_Doc(del_id_str);
}

void ocall_retrieve_M_c(unsigned char * _u_prime, size_t _u_prime_size,
                              unsigned char *_v_prime, size_t maxLen,
                              int *_v_prime_size, size_t int_len){

	std::string u_prime_str((char*)_u_prime,_u_prime_size);
	std::string v_prime_str = myServer->Retrieve_M_c(u_prime_str);

	*_v_prime_size = (int)v_prime_str.size(); 
	memcpy(_v_prime,(unsigned char*)v_prime_str.c_str(),v_prime_str.size());

}

void ocall_del_M_c_value(const unsigned char *_u_prime, size_t _u_prime_size){

	std::string del_u_prime((char*)_u_prime,_u_prime_size);
	myServer->Del_M_c_value(del_u_prime);
}

void ocall_query_tokens_entries(const void *Q_w_u_arr,
                               const void *Q_w_id_arr,
                               int pair_count, int rand_size){
	
	std::vector<std::string> Res;
	Res = myServer->retrieve_query_results(
								(rand_t *)Q_w_u_arr,(rand_t *)Q_w_id_arr,
								pair_count);
	
	//give to Client for decryption
	myClient->DecryptDocCollection(Res);
}


//main func
int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;

	/********************创建enclave环境****************************/
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}
	/**************************************************************/

	/* Setup Protocol*/
	//Client
	myClient= new Client();

	//Enclave
	unsigned char KFvalue[ENC_KEY_SIZE]; //文件密钥kF
	myClient->getKFValue(KFvalue);
	/**********************初始化enclave中数据结构******************/
	//生成Kw kc
	ecall_init(eid,KFvalue,(size_t)ENC_KEY_SIZE); 
	/**************************************************************/

	//Server	
	myServer= new Server();

	printf("Adding doc\n");
	
	/*** 处理插入操作Update Protocol with op = add */
	uint64_t start_add_time =  timeSinceEpochMillisec(); //插入操作开始时间
	for(int i=1;i <= total_file_no; i++){  //total_file_no
		//client read a document
		//printf("->%d",i);
		docContent *fetch_data;
		fetch_data = (docContent *)malloc(sizeof( docContent));
        //获取下一篇doc
		myClient->ReadNextDoc(fetch_data);

		//encrypt and send to Server
		entry *encrypted_entry;
		encrypted_entry = (entry*)malloc(sizeof(entry));
		
		encrypted_entry->first.content_length = fetch_data->id.id_length; //add dociId
		encrypted_entry->first.content = (char*) malloc(fetch_data->id.id_length);
		encrypted_entry->second.message_length = fetch_data->content_length + AESGCM_MAC_SIZE + AESGCM_IV_SIZE;		
		encrypted_entry->second.message = (char *)malloc(encrypted_entry->second.message_length);

		//客户端对doc进行加密,结果存入entry
		myClient->EncryptDoc(fetch_data,encrypted_entry);
		
		//send(id,f) to server
		myServer->ReceiveEncDoc(encrypted_entry);
		
		//upload (op,id) to Enclave
		/*****************更新enclave中数据结构*************************/
		ecall_addDoc(eid,fetch_data->id.doc_id,fetch_data->id.id_length,
						fetch_data->content,fetch_data->content_length);
		/**************************************************************/

		//free memory 
		free(fetch_data->content);
		free(fetch_data->id.doc_id);
		free(fetch_data);

		free(encrypted_entry->first.content);
		free(encrypted_entry->second.message);
		free(encrypted_entry);
	}
	uint64_t end_add_time =  timeSinceEpochMillisec(); //插入操作结束时间
	std::cout << "********Time for adding********" << std::endl;
	std::cout << "Total time:" << end_add_time-start_add_time << " ms" << std::endl;
	std::cout << "Average time (file):" << (end_add_time-start_add_time)*1.0/total_file_no << " ms" << std::endl;
	std::cout << "Average time (pair):" << (end_add_time-start_add_time)*1.0/total_pair_no << " ms" << std::endl;

	//** 处理删除操作Update Protocol with op = del (id)
	printf("\nDeleting doc\n");
	uint64_t start_del_time =  timeSinceEpochMillisec(); //删除操作开始时间
	//docId* delV = new docId[del_no];
	docId delV_i; //docID:文件ID数据结构
	for(int del_index=1; del_index <=del_no; del_index++){
		//printf("->%s",delV_i[del_index].doc_id);
		myClient->Del_GivenDocIndex(del_index, &delV_i);
        /*****************在enclave中查询关键字*************************/
		ecall_delDoc(eid,delV_i.doc_id,delV_i.id_length);
        /**************************************************************/
	}
	uint64_t end_del_time =  timeSinceEpochMillisec(); //删除操作结束时间
	std::cout << "********Time for deleting********" << std::endl;
	std::cout << "Total time:" << end_del_time-start_del_time << " ms" << std::endl;
	std::cout << "Average time:" << (end_del_time-start_del_time)*1.0/del_no << " ms" << std::endl;

	free(delV_i.doc_id);

	// std::string s_keyword[2]= {"list","clinton"}; 
	std::string s_keyword[1]= {"bird"};
	int keyword_count = 1; //查询关键字的数量
	std::cout << "********Time for searching********" << std::endl;
	uint64_t total_search_time = 0;
	for (int s_i = 0; s_i < keyword_count; s_i++){
		std::cout << "Searching ==>" << s_keyword[s_i].c_str() << std::endl;
		// printf("\nSearching ==> %s\n", s_keyword[s_i].c_str());
		uint64_t start_time =  timeSinceEpochMillisec();
		// std::cout << timeSinceEpochMillisec() << std::endl;
        /*****************将文档id加入删除list*************************/
		ecall_search(eid, s_keyword[s_i].c_str(), s_keyword[s_i].size());
        /*****************将文档id加入删除list*************************/
        uint64_t end_time =  timeSinceEpochMillisec();
		// std::cout << timeSinceEpochMillisec() << std::endl;
		std::cout << "Elapsed time:" << end_time-start_time << " ms"  << std::endl;
		total_search_time += end_time-start_time;
	}
	std::cout << "Total time:" << total_search_time << " ms" << std::endl;
	std::cout << "Average time:" << total_search_time*1.0/keyword_count << " ms" << std::endl;

	delete myClient;
	delete myServer;

	return 0;
}

