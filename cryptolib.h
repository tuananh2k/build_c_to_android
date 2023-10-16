#pragma once
#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H

#ifdef __cplusplus 
extern "C" {
#endif 
	#include <wchar.h>

#ifdef _WINDLL
#define ZALO_CRYPTOLIB_API __declspec(dllexport)
#else
#define ZALO_CRYPTOLIB_API __declspec(dllimport)
#endif

#define MAX_PUBKEY_LEN			4096
#define MAX_RSA_MODULUS_BYTE	512
#define MAX_BUFF_LEN			4096

#define AES256_KEY_LENGTH		32

/**
* Ham ma hoa file
	Chuc nang:			ma hoa file de gui cho danh sach user

	Tham so:
	inputFileName		ten file ro dau vao (dung unicode cho ten file tieng viet)
	outputFileName		ten file ma dau ra (dung unicode cho ten file tieng viet)
	listUserID			danh sach ID cua USER
	listUserPubKey		danh sach pubkey cua USER (pubkey doc tu file dinh dang .pem, pubkey cua tung User phan biet bang dau ';')
	numUser				so luong User 

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/
	ZALO_CRYPTOLIB_API int Zalo_EncryptFile(const wchar_t *inputFileName, const wchar_t *outputFileName,
	unsigned int *listUserID, const char *listUserPubKey, unsigned int numUser);

/**
* Ham giai ma file
	Chuc nang:			giai ma file nhan duoc tu server

	Tham so:
	inputFileName		ten file ma dau vao (dung unicode cho ten file tieng viet)
	outputFileName		ten file giai ma dau ra (dung unicode cho ten file tieng viet)
	userID				ID cua USER
	userPrivKey			khoa bi mat cua user (doc tu file dinh dang .pem)
	userPrivKeyLen		do dai du lieu khoa bi mat user
	pass				mat khau khoa bi mat user (day cung chinh la mat khau dang nhap cua user)

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/

	ZALO_CRYPTOLIB_API int Zalo_DecryptFile(const wchar_t *inputFileName, const wchar_t *outputFileName, unsigned int userID,
	const char *userPrivKey, unsigned int userPrivKeyLen, const char *pass);

/**
* Ham doi mat khau private key
	Chuc nang:			doi mat khau khoa bi mat

	Tham so:
	inPrivKey			khoa bi mat dau vao (doc tu file dinh dang .pem)
	inPrivKeyLen		do dai du lieu khoa bi mat
	oldPass				mat khau khoa cu
	outPrivKey			khoa bi mat dau ra
	outPrivKeyLen		do dai du lieu khoa bi mat dau ra
	outPrivKeyMaxLen	do dai toi da du lieu khoa bi mat dau ra
	newPass				mat khau khoa moi

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/
	ZALO_CRYPTOLIB_API int Zalo_ChangePrivKeyPass(const char *inPrivKey, unsigned int inPrivKeyLen, const char *oldPass,
	char *outPrivKey, unsigned int *outPrivKeyLen, unsigned int outPrivKeyMaxLen, const char *newPass);

/**
* Ham ma hoa tin nhan
	Chuc nang:			ma hoa tin nhan de gui cho danh sach user

	Tham so:
	inMes				tin nhan ro dau vao (dung utf8 cho tin nhan tieng viet)
	inMesLen			do dai tin nhan ro dau vao
	outMes				ban ma tin nhan dau ra
	outMesLen			do dai ban ma tin nhan dau ra
	outMesMaxLen		do dai toi da cua ban ma tin nhan dau ra
	listUserID			danh sach ID cua USER
	listUserPubKey		danh sach pubkey cua USER (pubkey doc tu file dinh dang .pem, pubkey cua tung User phan biet bang dau ';')
	numUser				so luong User

	Tra ve:
	0				neu thanh cong
	khac			neu co loi

	Chu y: outMesMaxLen duoc tinh nhu sau:
	2*(4 + numUser*(4 + RSA_LENGTH) + 4 + inMesLen + 4 + HASH_LENGTH)
*/
	ZALO_CRYPTOLIB_API int Zalo_EncryptMessage(const unsigned char *inMes, unsigned int inMesLen,
	unsigned char *outMes, unsigned int *outMesLen, unsigned int outMesMaxLen,
	unsigned int *listUserID, const char *listUserPubKey, unsigned int numUser);

/**
* Ham giai ma tin nhan
	Chuc nang:			giai ma tin nhan nhan duoc tu server

	Tham so:
	inMes				ban ma tin nhan dau vao
	inMesLen			do dai ban ma tin nhan dau vao
	outMes				ban giai ma tin nhan dau ra (dung utf8 cho tin nhan tieng viet)
	outMesLen			do dai ban giai ma tin nhan dau ra
	outMesMaxLen		do dai toi da cua ban giai ma tin nhan dau ra
	userID				ID cua USER
	userPrivKey			khoa bi mat cua user (doc tu file dinh dang .pem)
	userPrivKeyLen		do dai du lieu khoa bi mat user
	pass				mat khau khoa bi mat user (day cung chinh la mat khau dang nhap cua user)

	Tra ve:
	0				neu thanh cong
	khac			neu co loi

*/

	ZALO_CRYPTOLIB_API int Zalo_DecryptMessage(const unsigned char *inMes, unsigned int inMesLen,
	unsigned char *outMes, unsigned int *outMesLen, unsigned int outMesMaxLen,
	unsigned int userID, const char* userPrivKey, unsigned int userPrivKeyLen, const char* pass);



	ZALO_CRYPTOLIB_API int Zalo_GenerateRSAKey(const char *pass, unsigned int bitlen,
		char *privKey, unsigned int *privKeyLen, unsigned int privKeyMaxLen,
		char *pubKey, unsigned int *pubKeyLen, unsigned int pubKeyMaxLen);


	ZALO_CRYPTOLIB_API const char *Zalo_Error(int errNum);


#ifdef __cplusplus
}
#endif

#endif