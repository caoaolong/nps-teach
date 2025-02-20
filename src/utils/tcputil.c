//
// Created by Administrator on 25-2-20.
//
#include <nps.h>

uint32_t gen_uint32_number() {
    HCRYPTPROV hCryptProv;
    unsigned int random_value;

    // 获取加密提供者句柄
    if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed\n");
        exit(1);
    }

    // 生成随机数
    if (!CryptGenRandom(hCryptProv, sizeof(random_value), (BYTE*)&random_value)) {
        printf("CryptGenRandom failed\n");
        CryptReleaseContext(hCryptProv, 0);
        exit(1);
    }

    // 释放加密提供者句柄
    CryptReleaseContext(hCryptProv, 0);
    return random_value;
}