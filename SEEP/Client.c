/*
 * Client.c
 *
 *  Created on: Nov 18, 2013
 *      Author: anders
 */
/* { define start } */
#define LTM_DESC
/* { define end } */
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>

#include <tomcrypt.h>
#include "Common.h"

int main(int argc, char *argv[])
{
	/* { fix start } */
	ltc_mp = ltm_desc;
	/* { fix end } */
    int sockfd = 0;

    struct sockaddr_in serv_addr;

    if(argc != 2)
    {
        printf("\n Usage: %s <ip of server> \n",argv[0]);
        return 1;
    }

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5002);

    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    }

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    }

    initEncrypt();
    ecc_key encryptKey;
    loadKey(&encryptKey, "bpublic.key");
    ecc_key decryptKey;
    loadKey(&decryptKey, "aprivate.key");

	/* { userString start } */
	printf("Enter message to send\n");
	unsigned char message[256];
	fgets((char*)message,256,stdin);
	/* { userString end } */

	/* { sendNonceA start } */
	int nonceA = randomNumber();
	printf("nonceA = %i\n",nonceA);
	printf("Encrypting nonceA with bpub\n");
	unsigned char nonceA_enc[2048];
	unsigned long outLength = 2048;
	ecc_encrypt((unsigned char*)&nonceA, sizeof(int), nonceA_enc, &outLength,&encryptKey);
	printf("Sending nonceA\n");
	write(sockfd, nonceA_enc, outLength);
	/* { sendNonceA end } */

	/* { resiveSessionKey start } */
	unsigned char recvBuff[1024];
	unsigned long msgLength;
	msgLength = recv(sockfd, recvBuff, sizeof(recvBuff),0);
	struct SessionKey sKey;
	unsigned long inLength = sizeof(struct SessionKey);
	ecc_decrypt(recvBuff,msgLength,(unsigned char*)&sKey,&inLength,&decryptKey);
	printf("Received sKey, nonceA = %i, key = %i\n", sKey.nonceA, sKey.key);
	/* { resiveSessionKey end } */

	/* { resendKey start } */
	my_aes_setup(sKey.key);
	sKey.nonceA ++;
	printf("Sending nonceA = %i encrypted with AES\n", sKey.nonceA);
	outLength = 2048;
	aes_encrypt((unsigned char*)&sKey.nonceA,sizeof(int),nonceA_enc, &outLength);
	write(sockfd, nonceA_enc, outLength);
	/* { resendKey end } */

	/* { sendMessage start } */
	printf("Sending message encrypted with AES\n");
	printf("%s", message);
	outLength = 2048;
	unsigned char message_enc[2048];
	aes_encrypt(message, strlen((char*)message), message_enc, &outLength);
	write(sockfd, message_enc, outLength);
	/* { sendMessage end } */
	
	return -1;

}



