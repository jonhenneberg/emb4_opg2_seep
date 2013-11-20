/*
 * Server.c
 *
 *  Created on: Nov 18, 2013
 *      Author: anders
 */
#define LTM_DESC

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <tomcrypt.h>
#include "Common.h"

int main(int argc, char *argv[])
{
	ltc_mp = ltm_desc;
	printf("Starting server\n");
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;


    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5002);
    printf("Server is running\n");

    if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0){
    	printf("Error binding to socket port");
    	return -1;
    }

    initEncrypt();
	ecc_key encryptKey;
	loadKey(&encryptKey, "apublic.key");
	ecc_key decryptKey;
	loadKey(&decryptKey, "bprivate.key");


    if(listen(listenfd, 10) != 0){
		printf("Error listen to socket");
		return -1;
	}

while(1)
{
	connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
	
	/* { resiveNonceA start } */
	unsigned char recvBuff[1024];
	unsigned long msgLength;
	msgLength = recv(connfd, recvBuff, sizeof(recvBuff),0);
	printf("Received nonceA\n");
	int nonceA;
	unsigned long inLength = sizeof(int);
	ecc_decrypt(recvBuff,msgLength,(unsigned char*)&nonceA,&inLength,&decryptKey);
	printf("nonceA = %i\n",nonceA);
	/* { resiveNonceA end } */
	
	/* { sendSessionKey start } */
	struct SessionKey sKey;
	sKey.nonceA = nonceA+1;
	sKey.key = randomNumber();
	unsigned char sKey_enc[2048];
	unsigned long outLength = 2048;
	ecc_encrypt((unsigned char*)&sKey, sizeof(struct SessionKey), sKey_enc, &outLength, &encryptKey);
	printf("Sending sKey, nonceA = %i, key = %i\n", sKey.nonceA, sKey.key);
	write(connfd, sKey_enc, outLength);
	/* { sendSessionKey end } */

	my_aes_setup(sKey.key);
	int newNonceA;
	msgLength = recv(connfd, recvBuff, sizeof(recvBuff),0);
	aes_decrypt(recvBuff,msgLength, (unsigned char*)&newNonceA, sizeof(int));
	printf("Received newNonceA = %i\n",newNonceA);

	/* { reseiveMessage start } */
	msgLength = recv(connfd, recvBuff, sizeof(recvBuff),0);
	unsigned char message[256];
	aes_decrypt(recvBuff,msgLength, message, sizeof(message));
	printf("Received message: %s\n",message);
	/* { reseiveMessage end } */




	close(connfd);
	sleep(1);
 }
}

