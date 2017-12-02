#pragma once

#include <stdint.h>

#pragma pack(push, 1)
enum EFF_IntegrityAlgorithm {
	EFF_IntegrityAlgorithm_None = 0,
};

enum EFF_EncryptionAlgorithm {
	EFF_EncryptionAlgorithm_None = 0,
	EFF_EncryptionAlgorithm_AES128_GCM = 3,
};

enum EFF_CompressionAlgorithm {
	EFF_CompressionAlgorithm_None = 0,
};

struct EFF_AlgorithmID {
	uint8_t Encryption;
	uint8_t Integrity;
	uint8_t Compression;
};

struct EFF_MagicHeader {
	uint8_t First;
	uint8_t Second;
	uint8_t Version;
};

struct EFF_Header {
	EFF_MagicHeader Identifier;
	uint32_t EncryptedLength;
	uint32_t FileLength;
	EFF_AlgorithmID	Algorithms;
	uint8_t Extensions;
};

#pragma pack(pop)