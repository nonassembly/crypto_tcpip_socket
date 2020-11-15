#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "openssl/applink.c"
#pragma comment(lib, "ws2_32.lib")

#define BUF_SIZE 1024

unsigned WINAPI sendMsg(void* arg);
unsigned WINAPI recvMsg(void* arg);
int aesEncrypt(unsigned char* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int aesDecrypt(unsigned char* ciphertext, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
void ErrorHandling(char* message);

int main(int argc, char* argv[])
{
	WSADATA wsaData;
	SOCKET hSocket;
	SOCKADDR_IN servAddr;

	char serverPublicKey[BUF_SIZE];
	BIO* bio = BIO_new_mem_buf(serverPublicKey, -1);
	
	RSA* rsaPublicKey;
	char name[50];
	char password[50];
	char encryptedName[BUF_SIZE];
	char encryptedPass[BUF_SIZE];

	int publicKeyLen, len;
	int authResult=0;

	char keyIv[49];
	char encryptedKeyIv[BUF_SIZE];
	EVP_CIPHER_CTX* ctx;
	int cipherTextLen;
	char iv[17];
	char symmetricKey[33];

	HANDLE sendThread, recvThread;
	typedef struct {
		SOCKET hSocket;
		char* iv;
		char* symmetricKey;
	} multipleArg;
	multipleArg* arg = (multipleArg*)malloc(sizeof(multipleArg));


	if(argc!=3)
	{
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}
/************************************ 소켓 생성, 서버 연결 ***************************************/
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		ErrorHandling("WSAStartup() error!");  
	
	hSocket=socket(PF_INET, SOCK_STREAM, 0);
	if(hSocket==INVALID_SOCKET)
		ErrorHandling("socket() error");
	
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family=AF_INET;
	servAddr.sin_addr.s_addr=inet_addr(argv[1]);
	servAddr.sin_port=htons(atoi(argv[2]));
	
	if(connect(hSocket, (SOCKADDR*)&servAddr, sizeof(servAddr))==SOCKET_ERROR)
		ErrorHandling("connect() error!");
	printf("TCP 연결 완료\n");
/************************************ 소켓 생성, 서버 연결 ***************************************/
/********************************* 공개키 수신, 패스워드 인증 ************************************/
	publicKeyLen = recv(hSocket, serverPublicKey, sizeof(serverPublicKey), 0);
	rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	printf("공개키 수신 완료\n");
	if (publicKeyLen == -1)
		ErrorHandling("read() error!");
	
	while (authResult==0)
	{
		printf("이름 : ");
		scanf_s("%s", name, sizeof(name));
		printf("패스워드 : ");
		scanf_s("%s", password, sizeof(password));
		len = RSA_public_encrypt(sizeof(name), name, encryptedName, rsaPublicKey, RSA_PKCS1_OAEP_PADDING);
		send(hSocket, encryptedName, len, 0);

		len = RSA_public_encrypt(sizeof(password), password, encryptedPass, rsaPublicKey, RSA_PKCS1_OAEP_PADDING);
		send(hSocket, encryptedPass, len, 0);

		len = recv(hSocket, &authResult, sizeof(authResult), 0);
		if (authResult == 0)
		{
			printf("인증 실패, 재입력\n");
		}
	}
/********************************* 공개키 수신, 패스워드 인증 ************************************/
/*********************************** 대칭키, iv 생성, 송신 ***************************************/
	srand((unsigned int)time(0));
	for (int i = 0; i < sizeof(keyIv)-1; i++)
	{
		keyIv[i] = rand() % 26 + 'a';
	}
	keyIv[sizeof(keyIv) - 1] = NULL;
	len = RSA_public_encrypt(sizeof(keyIv), keyIv, encryptedKeyIv, rsaPublicKey, RSA_PKCS1_OAEP_PADDING);
	send(hSocket, encryptedKeyIv, len, 0);
	printf("%s\n", keyIv);
	for (int i = 0; i < 32; i++)
	{
		symmetricKey[i] = keyIv[i];
	}
	symmetricKey[32] = '\0';
	for (int i = 32; i < 48; i++)
	{
		iv[i - 32] = keyIv[i];
	}
	iv[16]= '\0';
/*********************************** 대칭키, iv 생성, 송신 ***************************************/
/************************************** 메시지 송수신 ********************************************/
	arg->hSocket = hSocket;
	arg->symmetricKey = symmetricKey;
	arg->iv = iv;
	sendThread = (HANDLE)_beginthreadex(NULL, 0, sendMsg, (void*)arg, 0, NULL);
	recvThread = (HANDLE)_beginthreadex(NULL, 0, recvMsg, (void*)arg, 0, NULL);

	WaitForSingleObject(recvThread, INFINITE);
/************************************** 메시지 송수신 ********************************************/
	BIO_free(bio);
	closesocket(hSocket);
	WSACleanup();
	return 0;
}

void ErrorHandling(char* message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

unsigned WINAPI sendMsg(void* arg) {
	typedef struct {
		SOCKET hSocket;
		char* iv;
		char* symmetricKey;
	}multipleArg;
	multipleArg* arguments = (multipleArg*)arg;
	char* encryptedText[BUF_SIZE];

	SOCKET sock = arguments->hSocket;
	char* symmetricKey = arguments->symmetricKey;
	char* iv = arguments->iv;

	char msg[BUF_SIZE];
	char cipherText[BUF_SIZE];
	int len;

	while (1) {
		fgets(msg, BUF_SIZE, stdin);
		if (!strcmp(msg, "quit\n")) {
			closesocket(sock);
			exit(0);
		}
		len = aesEncrypt(msg, symmetricKey, iv, encryptedText);
		send(sock, encryptedText, len, 0);
	}
	return 0;
}

unsigned WINAPI recvMsg(void* arg) {
	typedef struct {
		SOCKET hSocket;
		char* iv;
		char* symmetricKey;
	}multipleArg;
	multipleArg* arguments = (multipleArg*)arg;
	char decryptedText[BUF_SIZE];

	SOCKET sock = arguments->hSocket;
	char* symmetricKey = arguments->symmetricKey;
	char* iv = arguments->iv;

	char msg[BUF_SIZE];
	int strLen;

	while (1) {
		strLen = recv(sock, msg, BUF_SIZE - 1, 0);
		if (strLen == -1)
			return -1;
		msg[strLen] = 0;
		strLen=aesDecrypt(msg, symmetricKey, iv, decryptedText);
		decryptedText[strLen-1] = '\0';
		printf("%s\n", decryptedText);
	}
	return 0;
}

int aesEncrypt(unsigned char* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertext)
{
	EVP_CIPHER_CTX* ctx;
	int len = 0;
	int ciphertext_len;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext));
	ciphertext_len = len;
	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int aesDecrypt(unsigned char* ciphertext, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx;
	int len;
	int plaintext_len;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, strlen(ciphertext));
	plaintext_len = len;
	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}