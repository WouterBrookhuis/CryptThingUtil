// CryptThingUtil.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "mbedtls\aes.h"
#include "mbedtls\gcm.h"
#include "mbedtls\sha256.h"
#include "mbedtls\md.h"
#include "Platform.h"

#include <iostream>
#include <fstream>
#include <string>
#include "FileStructs.h"

#define CTU_GCM_IS_NULL					0

#define CTU_ERR_OPENING_INPUT_FILE		-1
#define CTU_ERR_OPENING_OUTPUT_FILE		-2

#define CTU_CURRENT_VERSION				1

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = (unsigned char *)v; while (n--) *p++ = 0;

}
static int tls_prf_generic(mbedtls_md_type_t md_type,
	const unsigned char *secret, size_t slen,
	const char *label,
	const unsigned char *random, size_t rlen,
	unsigned char *dstbuf, size_t dlen)
{
	size_t nb;
	size_t i, j, k, md_len;
	unsigned char tmp[128];
	unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t md_ctx;
	int ret;

	mbedtls_md_init(&md_ctx);

	if ((md_info = mbedtls_md_info_from_type(md_type)) == NULL)
		return(-1);

	md_len = mbedtls_md_get_size(md_info);

	if (sizeof(tmp) < md_len + strlen(label) + rlen)
		return(-1);

	nb = strlen(label);
	memcpy(tmp + md_len, label, nb);
	memcpy(tmp + md_len + nb, random, rlen);
	nb += rlen;

	/*
	* Compute P_<hash>(secret, label + random)[0..dlen]
	*/
	if ((ret = mbedtls_md_setup(&md_ctx, md_info, 1)) != 0)
		return(ret);

	mbedtls_md_hmac_starts(&md_ctx, secret, slen);
	mbedtls_md_hmac_update(&md_ctx, tmp + md_len, nb);
	mbedtls_md_hmac_finish(&md_ctx, tmp);

	for (i = 0; i < dlen; i += md_len)
	{
		mbedtls_md_hmac_reset(&md_ctx);
		mbedtls_md_hmac_update(&md_ctx, tmp, md_len + nb);
		mbedtls_md_hmac_finish(&md_ctx, h_i);

		mbedtls_md_hmac_reset(&md_ctx);
		mbedtls_md_hmac_update(&md_ctx, tmp, md_len);
		mbedtls_md_hmac_finish(&md_ctx, tmp);

		k = (i + md_len > dlen) ? dlen % md_len : md_len;

		for (j = 0; j < k; j++)
			dstbuf[i + j] = h_i[j];
	}

	mbedtls_md_free(&md_ctx);

	mbedtls_zeroize(tmp, sizeof(tmp));
	mbedtls_zeroize(h_i, sizeof(h_i));

	return(0);
}

#if defined(MBEDTLS_SHA256_C)
static int tls_prf_sha256(const unsigned char *secret, size_t slen,
	const char *label,
	const unsigned char *random, size_t rlen,
	unsigned char *dstbuf, size_t dlen)
{
	return(tls_prf_generic(MBEDTLS_MD_SHA256, secret, slen,
		label, random, rlen, dstbuf, dlen));
}
#endif /* MBEDTLS_SHA256_C */


int CTU_gcm_update(mbedtls_gcm_context *ctx,
	size_t length,
	const unsigned char *input,
	unsigned char *output)
{
#if CTU_GCM_IS_NULL
	int result = mbedtls_gcm_update(ctx, length, input, output);
	memcpy(output, input, length);
	return result;
#else
	return mbedtls_gcm_update(ctx, length, input, output);
#endif
}

/**
* \brief			Expand a password string into encryption keys
*/
bool CTU_ExpandKey(std::string const &Key, void *Expanded, size_t Length)
{
	size_t length = Key.length();
	const unsigned char *c_key = (const unsigned char *)Key.c_str();
	unsigned char buf[32];
	// key_block = PRF(SHA256(password), "keyblock", SHA256(password), key_block_length)
	mbedtls_sha256(c_key, length, buf, 0);
	if (tls_prf_sha256(buf, 32, "keyblock", buf, 32, (unsigned char *)Expanded, Length) != 0) {
		return false;
	}
	return true;
}

/**
* \brief           File data encryption with GCM
*
* \param in		   The input file, pointing to the start of the file
* \param out	   The output file, pointing to where the encrypted file data should begin
* \param key       128 bit encryption key
* \param iv        128 bit IV
* \param inLength  Amount of data to decrypt from the input file
* \param outLength Amount of data to output to file
*
* \return          TRUE if successful
*/
bool CTU_DecryptData(std::ifstream &in, std::ofstream &out, const unsigned char *key, const unsigned char * iv, size_t inLength, size_t outLength)
{
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);

	unsigned char bufIn[16];
	unsigned char bufOut[16];
	unsigned char tag[16];

	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
		mbedtls_gcm_free(&ctx);
		return false;
	}

	if (mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, iv, 16, NULL, 0) != 0) {
		mbedtls_gcm_free(&ctx);
		return false;
	}

	// Input MUST be full blocks and output length can never be the same or larger than input due to padding
	if (inLength % 16 != 0 || outLength >= inLength) {
		return false;
	}

	size_t inBytes = 0;
	size_t blockBytes;
	bool finished = false;
	while (in.good() && out.good() && !finished) {
		// Read a block, decrypt it, output block
		in.read((char *)bufIn, 16);
		blockBytes = in.gcount();
		inBytes += blockBytes;

		if (blockBytes > 0) {
			// Decrypt data and write it
			if (CTU_gcm_update(&ctx, 16, bufIn, bufOut) != 0) {
				mbedtls_gcm_free(&ctx);
				return false;
			}
			// If this is the last block
			if (inBytes >= outLength) {
				// Do not write padding to output
				out.write((const char *)bufOut, 16 -(inBytes - outLength));
				finished = true;
				if (inBytes == outLength) {
					// There is still a padding block left to process
					in.read((char *)bufIn, 16);
					if (CTU_gcm_update(&ctx, 16, bufIn, bufOut) != 0) {
						mbedtls_gcm_free(&ctx);
						return false;
					}
				}
			}
			else {
				// Write whole block
				out.write((const char *)bufOut, 16);
			}
		}
		else {
			// Unexpected EOF
		}
	}

	if (finished) {
		// Calculate and compare tag
		if (mbedtls_gcm_finish(&ctx, tag, 16) != 0) {
			mbedtls_gcm_free(&ctx);
			return false;
		}
		// Tag is next in input file
		in.read((char *)bufIn, 16);
		blockBytes = in.gcount();
		// Compare tags
		if (blockBytes != 16 || memcmp(bufIn, tag, 16) != 0) {
			mbedtls_gcm_free(&ctx);
			return false;
		}

		// Check padding in last block
		uint8_t padding = bufOut[15];
		for (int i = 15 - padding; i < 16; i++) {
			if (bufOut[i] != padding) {
				mbedtls_gcm_free(&ctx);
				return false;
			}
		}
	}

	mbedtls_gcm_free(&ctx);

	return finished;
}

/**
* \brief           File data encryption with GCM
*
* \param in		   The input file, pointing to the start of the file
* \param out	   The output file, pointing to where the encrypted file data should begin
* \param key       128 bit encryption key
* \param iv        128 bit IV
* \param outLength Amount of data written to the output file EXCLUDING 16 byte GCM tag
* \param inLength  Amount of data read from the input file
*
* \return          TRUE if successful
*/
bool CTU_EncryptData(std::ifstream &in, std::ofstream &out, const unsigned char *key, const unsigned char * iv, size_t *outLength, size_t *inLength)
{
	/*
	This creates an EncryptedFile
	*/
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);

	unsigned char bufIn[16];
	unsigned char bufOut[16];
	unsigned char tag[16];

	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
		mbedtls_gcm_free(&ctx);
		return false;
	}

	if (mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, 16, NULL, 0) != 0) {
		mbedtls_gcm_free(&ctx);
		return false;
	}

	// Keep track of starting point for length calculation
	auto outStartP = out.tellp();

	size_t inBytes = 0;
	size_t amountRead;
	bool finished = false;
	while (in.good() && out.good() && !finished) {
		// Read a block, encrypt it, output block
		in.read((char *)bufIn, 16);
		amountRead = in.gcount();
		inBytes += amountRead;
		
		// Check if we got anything from the file
		if (amountRead > 0) {
			if (amountRead < 16) {
				// Last block, needs padding added to bufIn
				memset(&bufIn[amountRead], 16 - 1 - amountRead, 16 - amountRead);
			}
			// Encrypt and write block
			if (CTU_gcm_update(&ctx, 16, bufIn, bufOut) != 0) {
				mbedtls_gcm_free(&ctx);
				return false;
			}
			out.write((char *)bufOut, 16);
		}
		// If we didn't read a full block we're done
		if (amountRead < 16) {
			if (amountRead == 0) {
				// We need to add a full 16 byte padding block
				memset(bufIn, 0x0F, 16);
				if (CTU_gcm_update(&ctx, 16, bufIn, bufOut) != 0) {
					mbedtls_gcm_free(&ctx);
					return false;
				}
				out.write((char *)bufOut, 16);
			}
			// Finish up and write the tag
			finished = true;
			if (mbedtls_gcm_finish(&ctx, tag, 16) != 0) {
				mbedtls_gcm_free(&ctx);
				return false;
			}
			out.write((char *)tag, 16);
		}
	}

	mbedtls_gcm_free(&ctx);

	// Update outputted lengths
	*outLength = (size_t)(out.tellp() - outStartP) - 16;
	*inLength = inBytes;
	return finished;
}

void CTU_SetHeaderVersion(EFF_Header &Header, uint8_t Version)
{
	Header.Identifier.First = 0x0E;
	Header.Identifier.Second = 0xEF;
	Header.Identifier.Version = Version;
}

int CTU_GetHeaderVersion(EFF_Header Header)
{
	if (Header.Identifier.First == 0x0E &&
		Header.Identifier.Second == 0xEF) {
		return Header.Identifier.Version;
	}
	return -1;
}

bool CTU_ReadHeader(std::ifstream &File, EFF_Header &Header)
{
	if (!File.is_open()) {
		return false;
	}

	// Read header from start of file
	File.seekg(0);
	File.read((char *)&Header, sizeof(Header));

	Header.EncryptedLength = _byteswap_ulong(Header.EncryptedLength);
	Header.FileLength = _byteswap_ulong(Header.FileLength);
	return true;
}

bool CTU_WriteHeader(std::ofstream &File, EFF_Header Header)
{
	if (!File.is_open()) {
		return false;
	}

	// Write header to start of file
	File.seekp(0);
	Header.EncryptedLength = _byteswap_ulong(Header.EncryptedLength);
	Header.FileLength = _byteswap_ulong(Header.FileLength);
	File.write((char *)&Header, sizeof(Header));
	return true;
}

bool CTU_DecryptFile(std::string const &InFile, std::string const &OutFile, std::string const &Password)
{
	std::ifstream in;
	std::ofstream out;

	in.open(InFile, std::ios::in | std::ios::binary);

	if (!in.is_open()) {
		return false;
	}

	out.open(OutFile, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!out.is_open()) {
		in.close();
		return false;
	}

	// 16 bit key, 16 bit IV
	unsigned char keys[32];
	unsigned char *iv = &keys[16];
	if (!CTU_ExpandKey(Password, keys, 32)) {
		in.close();
		out.close();
		return false;
	}

	// Read header
	EFF_Header header;
	CTU_ReadHeader(in, header);
	// Check if we can process this file
	if (CTU_GetHeaderVersion(header) > CTU_CURRENT_VERSION ||
		header.Algorithms.Compression != EFF_CompressionAlgorithm_None ||
		header.Algorithms.Encryption != EFF_EncryptionAlgorithm_AES128_GCM ||
		header.Algorithms.Integrity != EFF_IntegrityAlgorithm_None) {
		in.close();
		out.close();
		return false;
	}

	// Read IV
	if (header.Identifier.Version >= 1) {
		in.read((char *)iv, 16);
	}

	// Decrypt file
	if (!CTU_DecryptData(in, out, keys, &keys[16], header.EncryptedLength, header.FileLength)) {
		out.clear();
		in.close();
		out.close();
		return false;
	}

	// Done
	in.close();
	out.close();
	return true;
}

bool CTU_EncryptFile(std::string const &InFile, std::string const &OutFile, std::string const &Password)
{
	std::ifstream in;
	std::ofstream out;

	in.open(InFile, std::ios::in | std::ios::binary);

	if (!in.is_open()) {
		return false;
	}

	out.open(OutFile, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!out.is_open()) {
		in.close();
		return false;
	}

	// 16 bit key
	unsigned char keys[16];
	if (!CTU_ExpandKey(Password, keys, 16)) {
		in.close();
		out.close();
		return false;
	}

	// 16 bit IV
	unsigned char iv[16];
	if (!CTU_Platform_GetCryptRandom(iv, 16)) {
		in.close();
		out.close();
		return false;
	}

	EFF_Header header;
	CTU_SetHeaderVersion(header, CTU_CURRENT_VERSION);
	header.Extensions = 0;
	header.Algorithms.Compression = EFF_CompressionAlgorithm_None;
	header.Algorithms.Encryption = EFF_EncryptionAlgorithm_AES128_GCM;
	header.Algorithms.Integrity = EFF_IntegrityAlgorithm_None;

	// Leave space for file header
	out.seekp(sizeof(header));

	// Write IV
	out.write((const char *)iv, 16);

	// Encrypt file
	size_t encryptedFileLength, inputFileLength;
	if (!CTU_EncryptData(in, out, keys, iv, &encryptedFileLength, &inputFileLength)) {
		out.clear();
		in.close();
		out.close();
		return false;
	}

	// Update header
	header.EncryptedLength = encryptedFileLength;
	header.FileLength = inputFileLength;
	CTU_WriteHeader(out, header);

	// Done
	in.close();
	out.close();
	return true;
}

enum CTU_State {
	CTU_State_Infile,
	CTU_State_Outfile,
	CTU_State_Password,
	CTU_State_Mode,
};

int main()
{
	CTU_State state = CTU_State_Infile;
	std::string input;

	std::string infile, outfile, password;
	
	std::cout << "File Crypto Util - Version: v" << std::to_string(CTU_CURRENT_VERSION) << " - Mode: AES128GCM\r\n";
	std::cout << "Type 'exit' to exit\r\n\r\n";

	bool exit = false;
	do {
		switch (state) {
		case CTU_State_Infile:
			std::cout << "Input file > ";
			break;
		case CTU_State_Outfile:
			std::cout << "Output file > ";
			break;
		case CTU_State_Password:
			std::cout << "Password > ";
			break;
		case CTU_State_Mode:
			std::cout << "Action (e/d): ";
			break;
		default:
			std::cout << "> ";
			break;
		}
		if (std::getline(std::cin, input)) {
			if (input.compare("exit") == 0) {
				exit = true;
			}
			else {
				switch (state) {
				case CTU_State_Infile:
					infile = input;
					state = CTU_State_Outfile;
					break;
				case CTU_State_Outfile:
					outfile = input;
					state = CTU_State_Password;
					break;
				case CTU_State_Password:
					password = input;
					state = CTU_State_Mode;
					break;
				case CTU_State_Mode:
					if (input.compare("e") == 0) {
						std::cout << "Encrypting " << infile << " to " << outfile << "\r\n";
						if (CTU_EncryptFile(infile, outfile, password)) {
							std::cout << "Encryption succesful!\r\n";
						}
						else {
							std::cout << "Encryption FAILED!\r\n";
						}
					}
					else if (input.compare("d") == 0) {
						std::cout << "Decrypting " << infile << " to " << outfile << "\r\n";
						if (CTU_DecryptFile(infile, outfile, password)) {
							std::cout << "Decryption succesful!\r\n";
						}
						else {
							std::cout << "Decryption FAILED!\r\n";
						}
					}
					else {
						std::cout << "Unknown mode " << input << "\r\n";
						break;
					}
					state = CTU_State_Infile;
					break;
				default:
					std::cout << "> ";
					break;
				}
			}
		}
	} while (!exit);
	
    return 0;
}

