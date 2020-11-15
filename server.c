#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "openssl/sha.h"
#include "openssl/applink.c"
#include <openssl/conf.h>
#include <openssl/evp.h>

#define BUF_SIZE 1024

void ErrorHandling(char* message);
void generatePublicKey();
char* getPublicKey();
char* getPrivateKey();
unsigned char* SHA256(const unsigned char* d);
void createSampleAccount(char* id, char* salt, char* pass);
int auth(char *id, char *pass);
unsigned WINAPI sendMsg(void* arg);
unsigned WINAPI recvMsg(void* arg);
int aesEncrypt(unsigned char* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int aesDecrypt(unsigned char* ciphertext, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

int main(int argc, char* argv[])
{
	WSADATA	wsaData;
	SOCKET hServSock, hClntSock;		
	SOCKADDR_IN servAddr, clntAddr;

	int szClntAddr, len;
	char* publicKey;
	char* privateKey;
	BIO* bio;
	RSA* rsaPrivateKey;

	char encryptedName[BUF_SIZE];
	char decryptedName[BUF_SIZE];
	char encryptedPass[BUF_SIZE];
	char decryptedPass[BUF_SIZE];
	int authResult = 0;

	char encryptedKeyIv[BUF_SIZE];
	char decryptedKeyIv[BUF_SIZE];
	char symmetricKey[33];
	char iv[17];

	HANDLE sendThread, recvThread;
	typedef struct {
		SOCKET hClntSock;
		char* iv;
		char* symmetricKey;
	} multipleArg;
	multipleArg* arg = (multipleArg*)malloc(sizeof(multipleArg));

	if(argc!=2) 
	{
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}
/******************************************* 소켓 생성 *******************************************/
	if(WSAStartup(MAKEWORD(2, 2), &wsaData)!=0)
		ErrorHandling("WSAStartup() error!"); 
	
	hServSock=socket(PF_INET, SOCK_STREAM, 0);
	if(hServSock==INVALID_SOCKET)
		ErrorHandling("socket() error");
  
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family=AF_INET;
	servAddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servAddr.sin_port=htons(atoi(argv[1]));
	
	if(bind(hServSock, (SOCKADDR*) &servAddr, sizeof(servAddr))==SOCKET_ERROR)
		ErrorHandling("bind() error");  
	
	if(listen(hServSock, 5)==SOCKET_ERROR)
		ErrorHandling("listen() error");
	printf("소켓 생성 완료\n리스닝 중\n");
	szClntAddr=sizeof(clntAddr);    	
	hClntSock=accept(hServSock, (SOCKADDR*)&clntAddr,&szClntAddr);
	if(hClntSock==INVALID_SOCKET)
		ErrorHandling("accept() error");  
	printf("클라이언트 접속\n");
/******************************************* 소켓 생성 ********************************************/
/******************************** 공개키 생성, 전송, password.txt 생성 ****************************/
	generatePublicKey();
	publicKey=getPublicKey();
	privateKey = getPrivateKey();
	bio = BIO_new_mem_buf(privateKey, -1);

	rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	send(hClntSock, publicKey, strlen(publicKey), 0);
	printf("공개키 송신 완료\n");

	createSampleAccount("user1", "salt1", "1234");
	createSampleAccount("user2", "salt2", "1111");
	createSampleAccount("user3", "salt3", "0000");
/********************************* 공개키 생성, password.txt 생성 *********************************/
/******************************** 암호&패스워드 수신, 해독, 검증 **********************************/
	while (authResult == 0)
	{
		len = recv(hClntSock, encryptedName, sizeof(encryptedName), 0);
		len = RSA_private_decrypt(len, encryptedName, decryptedName, rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);

		len = recv(hClntSock, encryptedPass, sizeof(encryptedPass), 0);
		len = RSA_private_decrypt(len, encryptedPass, decryptedPass, rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);

		authResult = auth(decryptedName, decryptedPass);
		send(hClntSock, &authResult, sizeof(authResult), 0);
	}
	printf("패스워드 인증 완료\n");
/******************************** 암호&패스워드 수신, 해독, 검증 **********************************/
/************************************** 대칭키 수신 **********************************************/
	len = recv(hClntSock, encryptedKeyIv, sizeof(encryptedKeyIv), 0);
	len = RSA_private_decrypt(len, encryptedKeyIv, decryptedKeyIv, rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);
	for (int i = 0; i < 32; i++)
	{
		symmetricKey[i] = decryptedKeyIv[i];
	}
	symmetricKey[32] = '\0';
	for (int i = 32; i < 48; i++)
	{
		iv[i-32] = decryptedKeyIv[i];
	}
	iv[16] = '\0';
/************************************** 대칭키 수신 **********************************************/
/************************************** 메시지 송수신 ********************************************/
	arg->hClntSock = hClntSock;
	arg->symmetricKey = symmetricKey;
	arg->iv = iv;
	sendThread = (HANDLE)_beginthreadex(NULL, 0, sendMsg, (void*)arg, 0, NULL);
	recvThread = (HANDLE)_beginthreadex(NULL, 0, recvMsg, (void*)arg, 0, NULL);
	
	WaitForSingleObject(recvThread, INFINITE);
/************************************** 메시지 송수신 ********************************************/
	BIO_free(bio);
	closesocket(hClntSock);
	closesocket(hServSock);
	WSACleanup();
	return 0;
}

void ErrorHandling(char* message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

void generatePublicKey()
{
	int keyLenInput = 2048;
	char outPublicKeyFile[50] = "PublicKey";
	char outPrivateKeyFile[50] = "PrivateKey";
	BIO* publicOut = NULL;
	BIO* privateOut = NULL;
	RSA* rsa = NULL;
	publicOut = BIO_new(BIO_s_file());
	privateOut = BIO_new(BIO_s_file());
	BIO_write_filename(publicOut, outPublicKeyFile);
	BIO_write_filename(privateOut, outPrivateKeyFile);
	RAND_status();
	rsa = RSA_generate_key(keyLenInput, RSA_F4, NULL, NULL);
	PEM_write_bio_RSA_PUBKEY(publicOut, rsa);
	PEM_write_bio_RSAPrivateKey(privateOut, rsa, NULL, NULL, 0, NULL, NULL);
	RSA_free(rsa);
	BIO_free_all(publicOut);
	BIO_free_all(privateOut);
}

char* getPublicKey()
{
	FILE* publicKeyFile;
	char* publicKey = (char*)malloc(sizeof(char) * 2048);
	char publicKeyTemp[1024];
	size_t len = 0;

	publicKeyFile = fopen("PublicKey", "r");
	while (1) {
		fgets(publicKeyTemp, 128, publicKeyFile);
		memcpy(publicKey + len, publicKeyTemp, strlen(publicKeyTemp));
		len += strlen(publicKeyTemp);
		if (strncmp(publicKeyTemp, "-----END PUBLIC KEY-----", 24) == 0)
		{
			memcpy(publicKey + len, "\0", 1);
			break;
		}
	}
	fclose(publicKeyFile);
	return publicKey;
}

char* getPrivateKey()
{
	FILE* privateKeyFile;
	char* privateKey = (char*)malloc(sizeof(char) * 2048);
	char privateKeyTemp[1024];
	size_t len = 0;
	
	privateKeyFile = fopen("PrivateKey", "r");
	
	while (1) {
		fgets(privateKeyTemp, 1024, privateKeyFile);
		memcpy(privateKey + len, privateKeyTemp, strlen(privateKeyTemp));
		len += strlen(privateKeyTemp);
		if (strncmp(privateKeyTemp, "-----END RSA PRIVATE KEY-----", 29) == 0)
		{
			memcpy(privateKey + len, "\0", 1);
			break;
		}
	}
	fclose(privateKeyFile);
	return privateKey;
}

void createSampleAccount(char* id, char* salt, char* pass)
{
	char saltedPass[55];
	char hashedPass[SHA256_DIGEST_LENGTH * 2];
	char* md;
	FILE* fp = fopen("password.txt", "a");

	strcpy(saltedPass, salt);
	strncat(saltedPass, pass, strlen(pass));
	md = SHA256(saltedPass);
	
	for (int i = 0; i < SHA256_DIGEST_LENGTH * 2; i+=2)
	{
		hashedPass[i + 1] = md[i/2] & 0x0f;
		hashedPass[i] = md[i/2]>>4 & 0x0f;
	}
	fprintf(fp, "%s %s ", id, salt);
	for (int i = 0; i < SHA256_DIGEST_LENGTH*2; i++)
	{
		fprintf(fp, "%X", hashedPass[i]);
	}
	fprintf(fp, "\n");
	fclose(fp);
}

char hex2ascii(char toconv)
{
	if (toconv < 0x0A)    toconv += 0x30;
	else        toconv += 0x37;
	return (toconv);
}

int auth(char *id, char *pass)
{
	char *line[150], *storedId = NULL, *salt = NULL, *hashedStoredPass = NULL; //password.txt 내용
	char saltedPass[55]; //솔트+사용자가 입력한 패스워드
	char hashedPass[SHA256_DIGEST_LENGTH * 2+1]; //saltedPass 해시
	char* md;

	FILE* fp = fopen("password.txt", "r");

	while(1)
	{
		fgets(line, BUF_SIZE, fp);
		if (feof(fp))
			break;
		storedId = strtok(line, " ");
		salt = strtok(NULL, " ");
		hashedStoredPass = strtok(NULL, " ");

		if (strncmp(id, storedId, -1)==0)
		{
			strcpy(saltedPass, salt);
			strncat(saltedPass, pass, strlen(pass));
			md = SHA256(saltedPass);
			
			for (int i = 0; i < SHA256_DIGEST_LENGTH * 2; i += 2)
			{
				hashedPass[i + 1] = hex2ascii(md[i / 2] & 0x0f);
				hashedPass[i] = hex2ascii(md[i / 2] >> 4 & 0x0f);
			}
			hashedPass[SHA256_DIGEST_LENGTH*2] = '\0';

			if (strncmp(hashedPass, hashedStoredPass, strlen(hashedPass))==0)
			{
				return 1;
			}
			else
				return 0;
		}

	}
	return 0;
}

unsigned char* SHA256(const unsigned char* d)
{
	SHA256_CTX c;
	static unsigned char md[SHA256_DIGEST_LENGTH];

	SHA256_Init(&c);
	SHA256_Update(&c, d, sizeof(d)+1);
	SHA256_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	return md;
}

unsigned WINAPI sendMsg(void* arg) {
	typedef struct  {
		SOCKET hClntSock;
		char* iv;
		char* symmetricKey;
	}multipleArg;
	multipleArg *arguments = (multipleArg*)arg;
	char* encryptedText[BUF_SIZE];
	
	SOCKET sock = arguments->hClntSock;
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
		len=aesEncrypt(msg, symmetricKey, iv, encryptedText);
		send(sock, encryptedText, len, 0);
	}
	return 0;
}

unsigned WINAPI recvMsg(void* arg) {
	typedef struct {
		SOCKET hClntSock;
		char* iv;
		char* symmetricKey;
	}multipleArg;
	multipleArg* arguments = (multipleArg*)arg;
	char decryptedText[BUF_SIZE];

	SOCKET sock = arguments->hClntSock;
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