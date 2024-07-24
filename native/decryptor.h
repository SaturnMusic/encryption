#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

char* base64_decode(const char* input, int length, int* output_length) {
    BIO* bio, * b64;
    char* output = (char*)malloc(length);
    if (output == NULL) {
        return NULL;
    }

    bio = BIO_new_mem_buf((void*)input, length);
    if (bio == NULL) {
        free(output);
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    *output_length = BIO_read(bio, output, length);
    if (*output_length <= 0) {
        free(output);
        BIO_free_all(bio);
        return NULL;
    }

    BIO_free_all(bio);

    output[*output_length] = '\0';

    return output;
}

void getKey(char* trackId, char* key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, trackId, strlen(trackId));
    MD5_Final(digest, &context);

    char MD5String[33];
    for (int i = 0; i < 16; i++)
        sprintf(&MD5String[i * 2], "%02x", (unsigned int)digest[i]);

    const char* base64_input = "ZzRlbDU4d2MwenZmOW5hMQ==";
    int decoded_length;
    char* decoded = base64_decode(base64_input, strlen(base64_input), &decoded_length);

    char secret[decoded_length];
    strcpy(secret, decoded);
    free(decoded);

    for (int i = 0; i < 16; i++)
        key[i] = MD5String[i] ^ MD5String[i + 16] ^ secret[i];
}

void decryptFile(char* decKey, const char* inputfn, const char* outputfn) {
    unsigned char* bfKey = reinterpret_cast<unsigned char*>(decKey);
    BF_KEY key;
    BF_set_key(&key, 16, bfKey);

    FILE* ofile = fopen(outputfn, "wb");
    FILE* ifile = fopen(inputfn, "rb");

    int i = 0;
    while (!feof(ifile)) {
        unsigned char buffer[2048];
        int read = fread(buffer, 1, 2048, ifile);
        if (i % 3 == 0 && read == 2048) {
            unsigned char decrypted[2048];
            unsigned char IV[8] = { 0,1,2,3,4,5,6,7 };
            BF_cbc_encrypt(buffer, decrypted, 2048, &key, IV, BF_DECRYPT);
            fwrite(decrypted, sizeof(unsigned char), sizeof(decrypted), ofile);
        }
        else {
            fwrite(buffer, sizeof(unsigned char), read, ofile);
        }
        i++;
    }
    fclose(ofile);
    fclose(ifile);
}

void decryptBytes(char* decKey, long length, unsigned char* data, unsigned char* output) {
    unsigned char* bfKey = reinterpret_cast<unsigned char*>(decKey);
    BF_KEY key;
    BF_set_key(&key, 16, bfKey);
    int count = length / 2048;

    int i = 0;
    for (i = 0; i < count; i++) {
        if (i % 3 == 0) {
            unsigned char buffer[2048];
            memcpy(buffer, &data[i * 2048], 2048);

            unsigned char decrypted[2048];
            unsigned char IV[8] = { 0,1,2,3,4,5,6,7 };
            BF_cbc_encrypt(buffer, decrypted, 2048, &key, IV, BF_DECRYPT);
            memcpy(&output[i * 2048], decrypted, 2048);
        }
        else {
            memcpy(&output[i * 2048], &data[i * 2048], 2048);
        }
    }
    if (length % 2048 != 0) {
        memcpy(&output[i * 2048], &data[i * 2048], (length - (i * 2048)));
    }
}