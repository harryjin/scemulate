#ifndef SCSNIFF_DATA_H
#define SCSNIFF_DATA_H

#include "packet.h"

enum data_t0_state {
    COMMAND = 0,
    PROCEDURE_BYTE,
    SW2,
    TRANSFER_ALL,
    TRANSFER_ONE,
};

// Signaled in lsb of TC1 in ATR when using T=1 protocol.
// 0 = LRC (default), 1 = CRC
enum data_t1_error_checking {
    LRC_XOR = 1,
    CRC_16 = 2,
};

struct data_t0 {
    enum data_t0_state state;
    unsigned command_bytes_seen;
    unsigned cla;
    unsigned ins;
    unsigned p1;
    unsigned p2;
    unsigned p3;
    unsigned p3_lc;
    unsigned p3_le;
    unsigned transfer_bytes_seen;
};

struct data_t1 {
    unsigned bytes_seen;
    unsigned msg_length;
    unsigned check_len;
    unsigned direction_from_card;
};

struct data {
    struct data_t0 t0;
    struct data_t1 t1;
};

struct iblocks {
    unsigned char data_buf[512];
    unsigned int data_len;
    unsigned int iblock_start;

    unsigned char iblock[512];
};

void data_init(struct data *data);

enum result t0_transfer_direction(struct data_t0 *data);

enum result data_t0_analyze(struct data *data, unsigned char byte);

enum result data_t1_analyze(struct data *data, unsigned char byte);

void generate_iblocks(struct iblocks *blks, unsigned char* apdu, unsigned len, unsigned ifs, unsigned char iN);
void next_iblock(struct iblocks *blks, unsigned ifs, unsigned char iN);
void change_iblock_index(struct iblocks *blks, unsigned char iN);
unsigned char gen_lrc(unsigned char *buf, unsigned len);

#endif // SCSNIFF_DATA_H
