#include <nps.h>
#include <time.h>

uint32_t gen_uint32_number() {
    /* 使用当前时间作为随机数种子 */
    srand((unsigned int)time(NULL));
    
    /* 生成随机数并确保它是32位无符号整数 */
    return (uint32_t)rand() | ((uint32_t)rand() << 16);
}