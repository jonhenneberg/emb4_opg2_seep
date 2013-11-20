/*
 * common.h
 *
 *  Created on: Nov 19, 2013
 *      Author: anders
 */
#include <tomcrypt.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <stdio.h>

#ifndef COMMON_H_
#define COMMON_H_
/* { SessionKey start } */
struct SessionKey{
	int nonceA;
	int key;
};
/* { SessionKey end } */

int randomNumber();
int loadKey(ecc_key* key, char* fileName);
void printCharArray(unsigned char* in, int long length);
int socketRecive(int sockfd, unsigned char* recvBuff);
void saveKeyToFile(ecc_key* key, char* fileName, int type);
int generateKeys(prng_state* prng);

int initEncrypt();
int ecc_encrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long* outLength, ecc_key* key);
int ecc_decrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long* outLength, ecc_key* key);
int my_aes_setup(int tmpKey);
int aes_encrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long* outLength);
int aes_decrypt(unsigned char* in, unsigned long inLength, unsigned char* out, unsigned long outLength);
#endif /* COMMON_H_ */
