#include <stdio.h>
#include <stdint.h>
// 初始置换IP
const int IP_table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};
// 逆置换IP^-1
const int IP_table_reverse[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};
// P盒
const int P_box[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10, 
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};
const int Pmax[32] = {
     9, 17, 23, 31, 13, 28,  2, 18,
    24, 16, 30,  6, 26, 20, 10,  1,
     8, 14, 25,  3,  4, 29, 11, 19,
    32, 12, 22,  7,  5, 27, 15, 21
};
// E扩展
const int E_box[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
}; 
const int Emax[8][2] = {
    {36, 38},
    {39},
    {40},
    {41, 43},
    {42, 44},
    {45},
    {46},
    {1, 47}
};
void get_table_E() {
    printf("{");
    uint8_t ui = 0;
    for (int j = 0; j < 256; j++) {
        uint64_t iop = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t bit = (ui >> (7 - i)) & 1;
            if (i == 0 || i == 3 || i == 4 || i == 7) {
                uint64_t ymp = (bit << (48 - Emax[i][0]));
                iop |= ymp;
                ymp = (bit << (48 - Emax[i][1]));
                iop |= ymp;
            } else {
                 uint64_t ymp = (bit << (48 - Emax[i][0]));
                iop |= ymp;
            }
        }
        printf("%#llXLL, ", iop);
        ui++;
    }
    printf("}");
}
void verification_E() {
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 2; j++) {
            if (Emax[i][j] == 0) {
                continue;
            } else {
                printf("%d, ", E_box[Emax[i][j]-1]);
            }
        }
    }
}
void get_table() {
    printf("{");
    uint8_t ui = 0;
    for (int j = 0; j < 256; j++) {
        uint64_t iop = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t bit = (ui >> (7 - i)) & 1;
            uint64_t ymp = (bit << (32 - Pmax[i + 8 * 3]));
            iop |= ymp;
        }
        printf("%#llXLL, ", iop);
        ui++;
    }
    printf("}");
}
void verification() {
    for (int i = 0; i < 32; i++) {
        printf("%d, ", P_box[Pmax[i]-1]);
    }
}
void opppp() {
    int lop[8] = {25, 26, 27, 28, 29, 30, 31, 32};
    for (int i = 0; i < 8; i++) {
        printf("%d: ", lop[i]);
        for (int j = 0; j < 48; j++) {
            if (E_box[j] == lop[i]) {
                printf("%d, ", j+1);
            }
        }
        printf("\n");
    }
}
int main() {
    
    get_table_E();
    //opppp();
    return 0;
}