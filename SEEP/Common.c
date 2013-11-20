/*
 * common.c
 *
 *  Created on: Nov 19, 2013
 *      Author: anders
 */
#include "Common.h"
/* { randomNumber start } */
int randomNumber(){
	srand(time(NULL));
	return rand();
}
/* { randomNumber end } */

/* { loadKey start } */
int loadKey(ecc_key* key, char* fileName){
	FILE *file;
	file = fopen(fileName,"rb");  // r for read, b for binary
	unsigned char keyArray[2048];
	unsigned long keyLength = 2048;
	fread((char*)&keyLength, 4,1,file);
	fread(keyArray, keyLength, 1, file);
	int err;
	if ((err = ecc_import(keyArray, keyLength, key)) != CRYPT_OK) {
		printf("Error import public key ,%i, %s\n",err, error_to_string(err));
		exit(EXIT_FAILURE);
	}
	return 1;
}
/* { loadKey end } */

void printCharArray(unsigned char* in, int long length){
	int i;
	for(i = 0; i < length; i++){
		printf("%02x ", in[i]);
	}
	printf("\n");
}

int socketRecive(int sockfd, unsigned char* recvBuff){
//	struct pollfd fds;
//	//char recvBuff[1024];
//
//	int n, x;
//	fds.fd = sockfd;
//	fds.events = POLL_IN;
//
//	x = recv(sockfd, recvBuff, 1024-1,0);
//	n = x;
//	while ( poll(&fds, 1, 10) > 0 && x > 0) {
//		x =recv(sockfd, &recvBuff[n], 1024-n,0);
//		n += x;
//	}
//	return n;
	return recv(sockfd, recvBuff, 1024-1,0);
}
/* { saveKeyToFile start } */
void saveKeyToFile(ecc_key* key, char* fileName, int type){
	int err;
	unsigned char keyArray[2048];
	unsigned long keyLength = 2048;
	if ((err = ecc_export(keyArray, &keyLength, type, key)) != CRYPT_OK) {
		printf("Error setting ,%i, %s\n",err, error_to_string(err));
		exit(EXIT_FAILURE);
	}
	FILE *file;
	file = fopen(fileName,"wb");  // w for write, b for binary
	fwrite((char*)&keyLength, 4,1,file);
	fwrite(keyArray,keyLength,1,file);
	fclose(file);
}
/* { saveKeyToFile end } */
/* { generateKeys start } */
int generateKeys(prng_state* prng){
	ecc_key key;
	int err;
	if ((err = ecc_make_key(prng,find_prng("fortuna"),24,&key))!= CRYPT_OK) {
		printf("Error setting up , %s\n", error_to_string(err));
		exit(EXIT_FAILURE);
	}
	saveKeyToFile(&key, "private.key", PK_PRIVATE);
	saveKeyToFile(&key, "public.key", PK_PUBLIC);
	return 0;
}
/* { generateKeys end } */
int prng_index;
int hash_index;
prng_state prng;
int initEncrypt(){
	prng_index = register_prng(&fortuna_desc);
	hash_index = register_hash(&sha256_desc);

	int err;
	if ((err = rng_make_prng(128, find_prng("fortuna"), &prng, NULL)) != CRYPT_OK) {
		printf("Error setting up PRNG, %s\n", error_to_string(err));
		exit(EXIT_FAILURE);
	}
	return 0;
}
/* { ecc_encrypt start } */
int ecc_encrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long* outLength, ecc_key* key){
	int err;
	if ((err = ecc_encrypt_key(in, inLength, out, outLength, &prng, prng_index, hash_index, key)) != CRYPT_OK) {
		printf("Error encrypting ,%i, %s\n",err, error_to_string(err));
		exit(EXIT_FAILURE);
	}
	return 0;
}
/* { ecc_encrypt end } */

/* { ecc_decrypt start } */
int ecc_decrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long* outLength, ecc_key* key){
	int err;
	if ((err = ecc_decrypt_key(in,inLength,out,outLength,key)) != CRYPT_OK) {
		printf("Error decrypting ,%i, %s\n",err, error_to_string(err));
		exit(EXIT_FAILURE);
	}
	return 0;
}
/* { ecc_decrypt end } */

/* { aes_setup start } */
symmetric_key symKey;
int my_aes_setup(int tmpKey){
	if (register_cipher(&aes_desc) == -1) {
		printf("Error registering aes\n");
		exit(EXIT_FAILURE);
	}
	
	unsigned char key[32];
	unsigned long keyLength = 32;
	hash_memory(hash_index,(unsigned char*)&tmpKey, sizeof(int), key, &keyLength);

	int err;
	if ((err = cipher_descriptor[find_cipher("aes")].setup(key, keyLength, 0, &symKey)) != CRYPT_OK) {
		printf("Error setting up AES ,%i, %s\n",err, error_to_string(err));
		exit(EXIT_FAILURE);
	}
	return 0;
}
/* { aes_setup end } */
int aes_encrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long* outLength){
	unsigned char pt[16];
	int i = 0;
	int err = 0;

	for(;i < inLength;i++){
		for(; i % 16 < 15; i++) {
			if(i >= inLength ){
				pt[i % 16] = 0;
			} else {
				pt[i % 16] = in[i];
			}
		}
		if(i >= inLength ){
			pt[i % 16] = 0;
		} else {
			pt[i % 16] = in[i];
		}


		if (i > *outLength) {
			printf("Error setting up AES ,%i, %s\n",err, error_to_string(CRYPT_BUFFER_OVERFLOW));
			exit(EXIT_FAILURE);
		}
		if ((err =rijndael_ecb_encrypt(pt,&out[i-15],&symKey)) != CRYPT_OK) {
			printf("Error setting up AES ,%i, %s\n",err, error_to_string(err));
			exit(EXIT_FAILURE);
		}
	}
	*outLength = i;
	return 0;
}

int aes_decrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long outLength){
	unsigned char pt[16];
	int i = 0;
	int err = 0;

	for(;i < outLength;i++){
		if ((err =rijndael_ecb_decrypt(&in[i],pt,&symKey)) != CRYPT_OK) {
			printf("Error setting up AES ,%i, %s\n",err, error_to_string(err));
			exit(EXIT_FAILURE);
		}

		for(; i % 16 < 15; i++) {
			if(i < outLength ){
				out[i] = pt[i % 16];
			}
		}
		if(i < outLength ){
			out[i] = pt[i % 16];
		}
	}
	return 0;
}

