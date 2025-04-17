// MainForm.h
#pragma once

#include <msclr/marshal_cppstd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <vector>
#include <random>

using namespace std;
using namespace std::chrono;

namespace AESEncryptionApp {

    using namespace System;
    using namespace System::ComponentModel;
    using namespace System::Collections;
    using namespace System::Windows::Forms;
    using namespace System::Data;
    using namespace System::Drawing;
    using namespace System::IO;

    const int LENGTH = 16;
#define Nb 4

    // Biến toàn cục
    int Nr = 0;
    int Nk = 0;

    // Các mảng S-box, InvS-box và Rcon
    const unsigned char SBOX[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    const unsigned char INV_SBOX[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    const unsigned char rcon[256] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };

    // Khai báo các hàm 
    void xorBlock(unsigned char* plaintext, unsigned char* ciphertext) {
        for (int i = 0; i < LENGTH; i++)
            plaintext[i] ^= ciphertext[i];
    }

    void SubBytes(unsigned char* state) {
        for (int i = 0; i < 16; i++) {
            state[i] = SBOX[state[i]];
        }
    }

    void InvSubBytes(unsigned char* state) {
        for (int i = 0; i < 16; i++) {
            state[i] = INV_SBOX[state[i]];
        }
    }

    void ShiftRows(unsigned char* state) {
        unsigned char temp;

        // Hàng 1: dịch 1 byte
        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;

        // Hàng 2: dịch 2 byte
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;

        // Hàng 3: dịch 3 byte
        temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }

    void InvShiftRows(unsigned char* state) {
        unsigned char temp;

        // Hàng 1: dịch ngược 1 byte
        temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;

        // Hàng 2: dịch ngược 2 byte
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;

        // Hàng 3: dịch ngược 3 byte
        temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }

    unsigned char GFMul(unsigned char a, unsigned char b) {
        unsigned char p = 0;
        unsigned char hi_bit_set;

        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1)
                p ^= a;

            hi_bit_set = (a & 0x80);
            a <<= 1;

            if (hi_bit_set == 0x80)
                a ^= 0x1b;

            b >>= 1;
        }

        return p;
    }

    void MixColumns(unsigned char* state) {
        unsigned char temp[4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = state[i * 4 + j];
            }

            state[i * 4 + 0] = GFMul(0x02, temp[0]) ^ GFMul(0x03, temp[1]) ^ temp[2] ^ temp[3];
            state[i * 4 + 1] = temp[0] ^ GFMul(0x02, temp[1]) ^ GFMul(0x03, temp[2]) ^ temp[3];
            state[i * 4 + 2] = temp[0] ^ temp[1] ^ GFMul(0x02, temp[2]) ^ GFMul(0x03, temp[3]);
            state[i * 4 + 3] = GFMul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ GFMul(0x02, temp[3]);
        }
    }

    void InvMixColumns(unsigned char* state) {
        unsigned char temp[4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = state[i * 4 + j];
            }

            state[i * 4 + 0] = GFMul(0x0e, temp[0]) ^ GFMul(0x0b, temp[1]) ^ GFMul(0x0d, temp[2]) ^ GFMul(0x09, temp[3]);
            state[i * 4 + 1] = GFMul(0x09, temp[0]) ^ GFMul(0x0e, temp[1]) ^ GFMul(0x0b, temp[2]) ^ GFMul(0x0d, temp[3]);
            state[i * 4 + 2] = GFMul(0x0d, temp[0]) ^ GFMul(0x09, temp[1]) ^ GFMul(0x0e, temp[2]) ^ GFMul(0x0b, temp[3]);
            state[i * 4 + 3] = GFMul(0x0b, temp[0]) ^ GFMul(0x0d, temp[1]) ^ GFMul(0x09, temp[2]) ^ GFMul(0x0e, temp[3]);
        }
    }

    void AddRoundKey(unsigned char* state, unsigned char* roundKey) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    void KeyExpansion(unsigned char* key, unsigned char* expandedKey) {
        int i, j;
        unsigned char temp[4], k;

        for (i = 0; i < Nk * 4; i++) {
            expandedKey[i] = key[i];
        }

        for (i = Nk; i < Nb * (Nr + 1); i++) {
            for (j = 0; j < 4; j++) {
                temp[j] = expandedKey[(i - 1) * 4 + j];
            }

            if (i % Nk == 0) {
                k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;

                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];

                temp[0] ^= rcon[i / Nk];
            }
            else if (Nk > 6 && i % Nk == 4) {
                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];
            }

            for (j = 0; j < 4; j++) {
                expandedKey[i * 4 + j] = expandedKey[(i - Nk) * 4 + j] ^ temp[j];
            }
        }
    }

    void EncryptBlock(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* expandedKey) {
        unsigned char state[16];

        for (int i = 0; i < 16; i++) {
            state[i] = plaintext[i];
        }

        AddRoundKey(state, expandedKey);

        for (int round = 1; round < Nr; round++) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, expandedKey + round * 16);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, expandedKey + Nr * 16);

        for (int i = 0; i < 16; i++) {
            ciphertext[i] = state[i];
        }
    }

    void DecryptBlock(unsigned char* ciphertext, unsigned char* plaintext, unsigned char* expandedKey) {
        unsigned char state[16];

        for (int i = 0; i < 16; i++) {
            state[i] = ciphertext[i];
        }

        AddRoundKey(state, expandedKey + Nr * 16);

        for (int round = Nr - 1; round > 0; round--) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expandedKey + round * 16);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, expandedKey);

        for (int i = 0; i < 16; i++) {
            plaintext[i] = state[i];
        }
    }
    String^ EncryptFile(String^ inputFilePath, String^ outputFilePath, String^ keyString, int keySize) {
        try {
            Nk = keySize / 4;
            Nr = Nk + 6;

            // Chuyển đổi String^ thành std::string
            std::string inputFile = msclr::interop::marshal_as<std::string>(inputFilePath);
            std::string outputFile = msclr::interop::marshal_as<std::string>(outputFilePath);
            std::string keyInput = msclr::interop::marshal_as<std::string>(keyString);

            // Chuẩn bị khóa
            unsigned char key[32] = { 0 };
            for (size_t i = 0; i < keyInput.length() && i < keySize; i++) {
                key[i] = keyInput[i];
            }

            // Tạo expanded key
            unsigned char expandedKey[240]; // Đủ lớn cho AES-256
            KeyExpansion(key, expandedKey);

            // Mở file đầu vào
            ifstream inFile(inputFile, ios::binary);
            if (!inFile) {
                return L"Không thể mở file đầu vào!";
            }

            // Mở file đầu ra
            ofstream outFile(outputFile, ios::binary);
            if (!outFile) {
                inFile.close();
                return L"Không thể tạo file đầu ra!";
            }

            // Đọc dữ liệu từ file đầu vào
            vector<unsigned char> buffer(1024);
            vector<unsigned char> fileContent;
            size_t bytesRead;

            while (inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
                bytesRead = inFile.gcount();
                fileContent.insert(fileContent.end(), buffer.begin(), buffer.begin() + bytesRead);
            }

            bytesRead = inFile.gcount();
            if (bytesRead > 0) {
                fileContent.insert(fileContent.end(), buffer.begin(), buffer.begin() + bytesRead);
            }

            inFile.close();

            // Thêm đệm PKCS#7
            int originalSize = fileContent.size();
            int paddedSize = originalSize + (16 - (originalSize % 16));
            fileContent.resize(paddedSize);

            int padValue = paddedSize - originalSize;
            for (int i = originalSize; i < paddedSize; i++) {
                fileContent[i] = padValue;
            }

            // Mã hóa từng block 16 bytes
            auto startTime = high_resolution_clock::now();

            // Tạo IV ngẫu nhiên thay vì IV cố định toàn 0
            unsigned char iv[16] = { 0 };
            // Tạo IV ngẫu nhiên (trong thực tế nên dùng CSPRNG, nhưng ở đây giữ đơn giản)
            srand((unsigned int)time(NULL));
            for (int i = 0; i < 16; i++) {
                iv[i] = rand() % 256;
            }

            // Tạo header xác thực - Sử dụng một chuỗi magic và checksum đơn giản
            unsigned char header[32] = { 0 };
            // Magic string "AES_ENCRYPTED_FILE" (16 bytes)
            const char* magic = "AES_ENCRYPTED_FILE";
            for (int i = 0; i < 16; i++) {
                header[i] = magic[i % 16];
            }

            // Tạo checksum đơn giản từ khóa (16 bytes)
            for (int i = 0; i < 16; i++) {
                header[16 + i] = key[i % keySize] ^ 0xAA; // XOR với một giá trị cố định
            }

            // Mã hóa header bằng khóa
            unsigned char encryptedHeader[32];
            for (int i = 0; i < 2; i++) { // Header có 2 blocks
                unsigned char tempBlock[16];
                unsigned char encBlock[16];

                // Sao chép block
                for (int j = 0; j < 16; j++) {
                    tempBlock[j] = header[i * 16 + j];
                }

                // XOR với IV hoặc block trước đó
                if (i == 0) {
                    xorBlock(tempBlock, iv);
                }
                else {
                    xorBlock(tempBlock, encryptedHeader + ((i - 1) * 16));
                }

                // Mã hóa
                EncryptBlock(tempBlock, encBlock, expandedKey);

                // Lưu kết quả
                for (int j = 0; j < 16; j++) {
                    encryptedHeader[i * 16 + j] = encBlock[j];
                }
            }

            // Ghi IV vào file đầu ra
            outFile.write(reinterpret_cast<char*>(iv), 16);

            // Ghi Header đã mã hóa vào file
            outFile.write(reinterpret_cast<char*>(encryptedHeader), 32);

            // Biến lưu block mã hóa trước đó (khởi tạo = block cuối của header)
            unsigned char previousBlock[16];
            for (int j = 0; j < 16; j++) {
                previousBlock[j] = encryptedHeader[16 + j];
            }

            // Mã hóa theo chế độ CBC
            unsigned char block[16];
            unsigned char encryptedBlock[16];

            for (size_t i = 0; i < fileContent.size(); i += 16) {
                // Sao chép block hiện tại
                for (int j = 0; j < 16; j++) {
                    block[j] = fileContent[i + j];
                }

                // XOR với block mã hóa trước đó
                xorBlock(block, previousBlock);

                // Mã hóa block
                EncryptBlock(block, encryptedBlock, expandedKey);

                // Cập nhật previous block cho block tiếp theo
                for (int j = 0; j < 16; j++) {
                    previousBlock[j] = encryptedBlock[j];
                }

                // Ghi block mã hóa vào file đầu ra
                outFile.write(reinterpret_cast<char*>(encryptedBlock), 16);
            }

            auto endTime = high_resolution_clock::now();
            auto duration = duration_cast<microseconds>(endTime - startTime);

            outFile.close();

            return L"Mã hóa hoàn tất, Thời gian:" + duration.count() / 1000.0 + " ms";
        }
        catch (Exception^ ex) {
            return L"Lỗi: " + ex->Message;
        }
    }

    //Kiểm tra header và checksum
    String^ DecryptFile(String^ inputFilePath, String^ outputFilePath, String^ keyString, int keySize) {
        try {
            Nk = keySize / 4;
            Nr = Nk + 6;

            // Chuyển đổi String^ thành std::string
            std::string inputFile = msclr::interop::marshal_as<std::string>(inputFilePath);
            std::string outputFile = msclr::interop::marshal_as<std::string>(outputFilePath);
            std::string keyInput = msclr::interop::marshal_as<std::string>(keyString);

            // Chuẩn bị khóa
            unsigned char key[32] = { 0 };
            for (size_t i = 0; i < keyInput.length() && i < keySize; i++) {
                key[i] = keyInput[i];
            }

            // Tạo expanded key
            unsigned char expandedKey[240]; // Đủ lớn cho AES-256
            KeyExpansion(key, expandedKey);

            // Mở file đầu vào
            ifstream inFile(inputFile, ios::binary);
            if (!inFile) {
                return L"Không thể mở file đầu vào";
            }

            // Xác định kích thước file
            inFile.seekg(0, ios::end);
            size_t fileSize = inFile.tellg();
            inFile.seekg(0, ios::beg);

            // File cần có ít nhất IV (16) + Header (32) + 1 block dữ liệu (16) = 64 bytes
            if (fileSize < 64 || fileSize % 16 != 0) {
                inFile.close();
                return L"File đầu vào không hợp lệ hoặc không phải file đã mã hóa";
            }

            // Đọc IV (16 bytes đầu tiên)
            unsigned char iv[16];
            inFile.read(reinterpret_cast<char*>(iv), 16);

            // Đọc header đã mã hóa (32 bytes tiếp theo)
            unsigned char encryptedHeader[32];
            inFile.read(reinterpret_cast<char*>(encryptedHeader), 32);

            // Giải mã header
            unsigned char decryptedHeader[32] = { 0 };

            // Giải mã block 1 của header
            unsigned char tempBlock[16];
            DecryptBlock(encryptedHeader, tempBlock, expandedKey);
            xorBlock(tempBlock, iv);
            for (int j = 0; j < 16; j++) {
                decryptedHeader[j] = tempBlock[j];
            }

            // Giải mã block 2 của header
            DecryptBlock(encryptedHeader + 16, tempBlock, expandedKey);
            xorBlock(tempBlock, encryptedHeader);
            for (int j = 0; j < 16; j++) {
                decryptedHeader[16 + j] = tempBlock[j];
            }

            // Kiểm tra magic string
            const char* magic = "AES_ENCRYPTED_FILE";
            bool validMagic = true;
            for (int i = 0; i < 16; i++) {
                if (decryptedHeader[i] != magic[i % 16]) {
                    validMagic = false;
                    break;
                }
            }

            // Kiểm tra checksum từ khóa
            bool validChecksum = true;
            for (int i = 0; i < 16; i++) {
                if (decryptedHeader[16 + i] != (key[i % keySize] ^ 0xAA)) {
                    validChecksum = false;
                    break;
                }
            }

            // Nếu header không hợp lệ, khóa không đúng
            if (!validMagic || !validChecksum) {
                inFile.close();
                return L"Giải mã thất bại: Khóa không chính xác";
            }

            // Mở file đầu ra
            ofstream outFile(outputFile, ios::binary);
            if (!outFile) {
                inFile.close();
                return L"Không thể tạo ra file đầu ra";
            }

            // Giải mã từng block
            auto startTime = high_resolution_clock::now();

            unsigned char encryptedBlock[16];
            unsigned char decryptedBlock[16];
            unsigned char previousBlock[16];

            // Lưu block cuối của header để dùng cho chuỗi CBC
            for (int i = 0; i < 16; i++) {
                previousBlock[i] = encryptedHeader[16 + i];
            }

            // Giải mã theo chế độ CBC, bỏ qua IV và header đã đọc
            while (inFile.read(reinterpret_cast<char*>(encryptedBlock), 16)) {
                // Lưu lại block mã hóa hiện tại để dùng cho block tiếp theo
                unsigned char currentBlock[16];
                for (int i = 0; i < 16; i++) {
                    currentBlock[i] = encryptedBlock[i];
                }

                // Giải mã block
                DecryptBlock(encryptedBlock, decryptedBlock, expandedKey);

                // XOR với block trước đó
                xorBlock(decryptedBlock, previousBlock);

                // Cập nhật block trước đó cho block tiếp theo
                for (int i = 0; i < 16; i++) {
                    previousBlock[i] = currentBlock[i];
                }

                // Ghi block giải mã vào file đầu ra
                outFile.write(reinterpret_cast<char*>(decryptedBlock), 16);
            }

            auto endTime = high_resolution_clock::now();
            auto duration = duration_cast<microseconds>(endTime - startTime);

            inFile.close();
            outFile.close();

            // Loại bỏ đệm PKCS#7
            std::fstream outFilePadding(outputFile, std::ios::in | std::ios::out | std::ios::binary);
            if (!outFilePadding) {
                return L"Không thể mở file đầu ra để loại bỏ đệm";
            }

            // Xác định kích thước file
            outFilePadding.seekg(0, std::ios::end);
            size_t outputSize = outFilePadding.tellg();

            if (outputSize > 0) {
                // Đọc byte cuối cùng để xác định giá trị đệm
                outFilePadding.seekg(outputSize - 1);
                unsigned char padValue;
                outFilePadding.read(reinterpret_cast<char*>(&padValue), 1);

                if (padValue > 0 && padValue <= 16) {
                    // Cắt bỏ phần đệm
                    outFilePadding.close();

                    std::fstream outFileTruncate(outputFile, std::ios::in | std::ios::out | std::ios::binary);
                    outFileTruncate.seekp(outputSize - padValue);
                    outFileTruncate.close();
                }
            }

            return L"Giải mã hoàn tất, thời gian: " + duration.count() / 1000.0 + " ms";
        }
        catch (Exception^ ex) {
            return L"Lỗi: " + ex->Message;
        }
    }

    String^ GenerateRandomKey(int keySize) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::uniform_int_distribution<> dis(0, chars.size() - 1);

        std::string randomKey;
        for (int i = 0; i < keySize; i++) {
            randomKey += chars[dis(gen)];
        }

        return gcnew String(randomKey.c_str());
    }

    ///
    ///============================================================================== HAM TAO GIAO DIEN==============================================================================
    ///
    public ref class MainForm : public System::Windows::Forms::Form
    {
    public:
        MainForm(void)
        {
            InitializeComponent();
        }

    protected:
        ~MainForm()
        {
            if (components)
            {
                delete components;
            }
        }

    private:
        System::ComponentModel::Container^ components;
        System::Windows::Forms::Label^ titleLabel;
        System::Windows::Forms::RadioButton^ encryptRadioButton;
        System::Windows::Forms::RadioButton^ decryptRadioButton;
        System::Windows::Forms::Label^ inputFileLabel;
        System::Windows::Forms::TextBox^ inputFileTextBox;
        System::Windows::Forms::Button^ browseInputButton;
        System::Windows::Forms::Label^ outputFileLabel;
        System::Windows::Forms::TextBox^ outputFileTextBox;
        System::Windows::Forms::Button^ browseOutputButton;
        System::Windows::Forms::Label^ keyLabel;
        System::Windows::Forms::TextBox^ keyTextBox;
        System::Windows::Forms::GroupBox^ keySizeGroupBox;
        System::Windows::Forms::RadioButton^ aes128RadioButton;
        System::Windows::Forms::RadioButton^ aes192RadioButton;
        System::Windows::Forms::RadioButton^ aes256RadioButton;
        System::Windows::Forms::Button^ processButton;
        System::Windows::Forms::Label^ statusLabel;
        System::Windows::Forms::OpenFileDialog^ openFileDialog;
        System::Windows::Forms::SaveFileDialog^ saveFileDialog;

#pragma region Windows Form Designer generated code
        void InitializeComponent(void)
        {
            this->components = gcnew System::ComponentModel::Container();
            this->Size = System::Drawing::Size(600, 500);
            this->Text = L"AES Encryption Tool";
            this->Padding = System::Windows::Forms::Padding(10);
            this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
            this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
            this->MaximizeBox = false;

            // Title Label
            this->titleLabel = gcnew System::Windows::Forms::Label();
            this->titleLabel->Text = L"AES Encryption and Decryption Tool";
            this->titleLabel->Font = gcnew System::Drawing::Font(L"Arial", 16, System::Drawing::FontStyle::Bold);
            this->titleLabel->Location = System::Drawing::Point(10, 20);
            this->titleLabel->Size = System::Drawing::Size(580, 30);
            this->titleLabel->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;

            // Mode Selection
            this->encryptRadioButton = gcnew System::Windows::Forms::RadioButton();
            this->encryptRadioButton->Text = L"Mã hóa";
            this->encryptRadioButton->Location = System::Drawing::Point(150, 60);
            this->encryptRadioButton->Size = System::Drawing::Size(100, 20);
            this->encryptRadioButton->Checked = true;

            this->decryptRadioButton = gcnew System::Windows::Forms::RadioButton();
            this->decryptRadioButton->Text = L"Giải mã";
            this->decryptRadioButton->Location = System::Drawing::Point(300, 60);
            this->decryptRadioButton->Size = System::Drawing::Size(100, 20);

            // Input File
            this->inputFileLabel = gcnew System::Windows::Forms::Label();
            this->inputFileLabel->Text = L"File đầu vào:";
            this->inputFileLabel->Location = System::Drawing::Point(20, 90);
            this->inputFileLabel->Size = System::Drawing::Size(100, 20);

            this->inputFileTextBox = gcnew System::Windows::Forms::TextBox();
            this->inputFileTextBox->Location = System::Drawing::Point(120, 90);
            this->inputFileTextBox->Size = System::Drawing::Size(350, 20);

            this->browseInputButton = gcnew System::Windows::Forms::Button();
            this->browseInputButton->Text = L"Chọn";
            this->browseInputButton->Location = System::Drawing::Point(480, 90);
            this->browseInputButton->Size = System::Drawing::Size(80, 25);
            this->browseInputButton->Click += gcnew System::EventHandler(this, &MainForm::BrowseInputButton_Click);

            // Output File
            this->outputFileLabel = gcnew System::Windows::Forms::Label();
            this->outputFileLabel->Text = L"File đầu ra:";
            this->outputFileLabel->Location = System::Drawing::Point(20, 130);
            this->outputFileLabel->Size = System::Drawing::Size(100, 20);

            this->outputFileTextBox = gcnew System::Windows::Forms::TextBox();
            this->outputFileTextBox->Location = System::Drawing::Point(120, 130);
            this->outputFileTextBox->Size = System::Drawing::Size(350, 20);

            this->browseOutputButton = gcnew System::Windows::Forms::Button();
            this->browseOutputButton->Text = L"Chọn";
            this->browseOutputButton->Location = System::Drawing::Point(480, 130);
            this->browseOutputButton->Size = System::Drawing::Size(80, 25);
            this->browseOutputButton->Click += gcnew System::EventHandler(this, &MainForm::BrowseOutputButton_Click);

            // Key
            this->keyLabel = gcnew System::Windows::Forms::Label();
            this->keyLabel->Text = L"Khóa:";
            this->keyLabel->Location = System::Drawing::Point(20, 170);
            this->keyLabel->Size = System::Drawing::Size(100, 20);

            this->keyTextBox = gcnew System::Windows::Forms::TextBox();
            this->keyTextBox->Location = System::Drawing::Point(120, 170);
            this->keyTextBox->Size = System::Drawing::Size(440, 20);

            // Key Size
            this->keySizeGroupBox = gcnew System::Windows::Forms::GroupBox();
            this->keySizeGroupBox->Text = L"Độ dài khóa";
            this->keySizeGroupBox->Location = System::Drawing::Point(120, 210);
            this->keySizeGroupBox->Size = System::Drawing::Size(350, 60);

            this->aes128RadioButton = gcnew System::Windows::Forms::RadioButton();
            this->aes128RadioButton->Text = L"AES-128";
            this->aes128RadioButton->Location = System::Drawing::Point(20, 25);
            this->aes128RadioButton->Size = System::Drawing::Size(100, 20);
            this->aes128RadioButton->Checked = true;

            this->aes192RadioButton = gcnew System::Windows::Forms::RadioButton();
            this->aes192RadioButton->Text = L"AES-192";
            this->aes192RadioButton->Location = System::Drawing::Point(130, 25);
            this->aes192RadioButton->Size = System::Drawing::Size(100, 20);

            this->aes256RadioButton = gcnew System::Windows::Forms::RadioButton();
            this->aes256RadioButton->Text = L"AES-256";
            this->aes256RadioButton->Location = System::Drawing::Point(240, 25);
            this->aes256RadioButton->Size = System::Drawing::Size(100, 20);

            this->keySizeGroupBox->Controls->Add(this->aes128RadioButton);
            this->keySizeGroupBox->Controls->Add(this->aes192RadioButton);
            this->keySizeGroupBox->Controls->Add(this->aes256RadioButton);

            // Process Button
            this->processButton = gcnew System::Windows::Forms::Button();
            this->processButton->Text = L"Xử lý";
            this->processButton->Location = System::Drawing::Point(230, 290);
            this->processButton->Size = System::Drawing::Size(120, 40);
            this->processButton->Click += gcnew System::EventHandler(this, &MainForm::ProcessButton_Click);

            // Status Label
            this->statusLabel = gcnew System::Windows::Forms::Label();
            this->statusLabel->Text = L"Sẵn sàng";
            this->statusLabel->Location = System::Drawing::Point(20, 340);
            this->statusLabel->Size = System::Drawing::Size(560, 40);
            this->statusLabel->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;

            // Dialogs
            this->openFileDialog = gcnew System::Windows::Forms::OpenFileDialog();
            this->openFileDialog->Filter = L"All Files (*.*)|*.*";
            this->openFileDialog->Title = L"Chọn file đầu vào";

            this->saveFileDialog = gcnew System::Windows::Forms::SaveFileDialog();
            this->saveFileDialog->Filter = L"All Files (*.*)|*.*";
            this->saveFileDialog->Title = L"Chọn file đầu ra";

            // Add controls to the form
            this->Controls->Add(this->titleLabel);
            this->Controls->Add(this->encryptRadioButton);
            this->Controls->Add(this->decryptRadioButton);
            this->Controls->Add(this->inputFileLabel);
            this->Controls->Add(this->inputFileTextBox);
            this->Controls->Add(this->browseInputButton);
            this->Controls->Add(this->outputFileLabel);
            this->Controls->Add(this->outputFileTextBox);
            this->Controls->Add(this->browseOutputButton);
            this->Controls->Add(this->keyLabel);
            this->Controls->Add(this->keyTextBox);
            this->Controls->Add(this->keySizeGroupBox);
            this->Controls->Add(this->processButton);
            this->Controls->Add(this->statusLabel);
        }
#pragma endregion

        // Xử lý sự kiện cho nút chọn file đầu vào
        void BrowseInputButton_Click(System::Object^ sender, System::EventArgs^ e)
        {
            if (this->openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
            {
                this->inputFileTextBox->Text = this->openFileDialog->FileName;

                // Tự động đề xuất tên file đầu ra
                String^ inputFile = this->openFileDialog->FileName;
                String^ extension = this->encryptRadioButton->Checked ? ".enc.txt" : ".dec.txt";
                String^ outputFile = System::IO::Path::Combine(
                    System::IO::Path::GetDirectoryName(inputFile),
                    System::IO::Path::GetFileNameWithoutExtension(inputFile) + extension);

                this->outputFileTextBox->Text = outputFile;
            }
        }

        // Xử lý sự kiện cho nút chọn file đầu ra
        void BrowseOutputButton_Click(System::Object^ sender, System::EventArgs^ e)
        {
            if (this->saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
            {
                this->outputFileTextBox->Text = this->saveFileDialog->FileName;
            }
        }

        // Xử lý sự kiện cho nút xử lý
        void ProcessButton_Click(System::Object^ sender, System::EventArgs^ e)
        {
            // Kiểm tra các trường nhập liệu
            if (String::IsNullOrEmpty(this->inputFileTextBox->Text))
            {
                MessageBox::Show(L"Vui lòng chọn file đầu vào.", L"Lỗi", MessageBoxButtons::OK, MessageBoxIcon::Error);
                return;
            }

            if (String::IsNullOrEmpty(this->outputFileTextBox->Text))
            {
                MessageBox::Show(L"Vui lòng chọn file đầu ra.", L"Lỗi", MessageBoxButtons::OK, MessageBoxIcon::Error);
                return;
            }

            if (String::IsNullOrEmpty(this->keyTextBox->Text))
            {
                int selectedKeySize = 16; // Mặc định AES-128
                if (this->aes192RadioButton->Checked)
                    selectedKeySize = 24;
                else if (this->aes256RadioButton->Checked)
                    selectedKeySize = 32;

                this->keyTextBox->Text = GenerateRandomKey(selectedKeySize);
                MessageBox::Show(L"Khóa ngẫu nhiên đã được tạo.", L"Thông báo", MessageBoxButtons::OK, MessageBoxIcon::Information);
            }

            // Kiểm tra độ dài khóa
            int selectedKeySize = 16; // Mặc định AES-128
            if (this->aes192RadioButton->Checked)
                selectedKeySize = 24;
            else if (this->aes256RadioButton->Checked)
                selectedKeySize = 32;

            // Tính độ dài khóa (theo byte)
            int actualKeyBytes = System::Text::Encoding::UTF8->GetByteCount(this->keyTextBox->Text);

            if (actualKeyBytes != selectedKeySize) {
                MessageBox::Show(
                    L"Khóa phải có độ dài " + selectedKeySize + L" bytes!\nĐộ dài hiện tại: " + actualKeyBytes + " bytes.",
                    L"Lỗi",
                    MessageBoxButtons::OK,
                    MessageBoxIcon::Error
                );
                return;
            }

            // Thực hiện mã hóa hoặc giải mã
            String^ result;
            if (this->encryptRadioButton->Checked)
            {
                this->statusLabel->Text = L"Đang mã hóa...";
                this->Refresh();
                result = EncryptFile(this->inputFileTextBox->Text, this->outputFileTextBox->Text, this->keyTextBox->Text, selectedKeySize);
            }
            else
            {
                this->statusLabel->Text = L"Đang giải mã...";
                this->Refresh();
                result = DecryptFile(this->inputFileTextBox->Text, this->outputFileTextBox->Text, this->keyTextBox->Text, selectedKeySize);
            }

            // Hiển thị kết quả
            this->statusLabel->Text = result;
            MessageBox::Show(result, L"Thông báo", MessageBoxButtons::OK, MessageBoxIcon::Information);
        }
    };
}