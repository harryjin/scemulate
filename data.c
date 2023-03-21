#include "data.h"

#include <string.h>

void data_init(struct data *data) {
    memset(data, 0, sizeof(struct data));
    data->t1.check_len = LRC_XOR;
}

enum result t0_transfer_direction(struct data_t0 *data) {
    switch (data->ins) {
        // First data transfer (if any) will be to the card.
        // Any return data will be read with GET RESPONSE.
        case 0x04: // DEACTIVATE FILE
        case 0x0E: case 0x0F: // ERASE BINARY
        case 0x20: case 0x21: // VERIFY
        case 0x22: // MANAGE SECURITY ENVIRONMENT/KEY DERIVATION
        case 0x24: // CHANGE REFERENCE DATA
        case 0x26: // DISABLE VERIFICATION REQUIREMENT
        case 0x28: // ENABLE VERIFICATION REQUIREMENT
        case 0x2C: // RESET RETRY COUNTER
        case 0x44: // ACTIVATE FILE
        case 0x82: // EXTERNAL or MUTUAL AUTHENTICATE
        case 0x86: case 0x87: // GENERAL AUTHENTICATE
        case 0x88: // INTERNAL AUTHENTICATE
        case 0xA1: // SEARCH BINARY
        case 0xA2: // SEARCH RECORD
        case 0xA8:
        case 0xAE:
        case 0xB1: // READ BINARY
        case 0xB3: // READ RECORD
        case 0xC2: case 0xC3: // ENVELOPE
        case 0xCB: // GET DATA
        case 0xD0: case 0xD1: // WRITE BINARY
        case 0xD2: // WRITE RECORD
        case 0xD6: case 0xD7: // UPDATE BINARY
        case 0xDA: case 0xDB: // PUT DATA
        case 0xDC: case 0xDD: // UPDATE RECORD
        case 0xE0: // CREATE FILE
        case 0xE2: // APPEND RECORD
        case 0xE4: // DELETE FILE
            return PACKET_TO_CARD;

        // First data transfer (if any) will be from the card.
        case 0x70: // MANAGE CHANNEL
        case 0x84: // GET CHALLENGE
        case 0xB0: // READ BINARY
        case 0xB2: // READ RECORD
        case 0xC0: // GET RESPONSE
        case 0xCA: // GET DATA
            return PACKET_FROM_CARD;

        case 0xA4: // SELECT
            // ISO 7816-4 Table 39: P1 meaning for SELECT command.
            switch (data->p1) {
                case 0x01: // Select child DF (data = DF identifier)
                case 0x02: // Select EF under current DF (data = EF identifier)
                case 0x04: // Select by DF name (data = app identifier)
                case 0x08: // Select from the MF (data = Path without MF id)
                case 0x09: // Select from the current DF
                           // (data = path without the current DF identifier)
                    return PACKET_TO_CARD;

                case 0x03: // Select parent DF of the current DF (data absent)
                    return PACKET_FROM_CARD;
            }
            break;
    }
    return PACKET_UNKNOWN;
}

enum result data_t0_analyze(struct data *data, unsigned char byte) {
    struct data_t0 *t0 = &data->t0;
    switch (t0->state) {
        case COMMAND:
            t0->command_bytes_seen++;
            if (t0->command_bytes_seen == 1) {
                t0->cla = byte;
            } if (t0->command_bytes_seen == 2) {
                t0->ins = byte;
            } else if (t0->command_bytes_seen == 3) {
                t0->p1 = byte;
            }else if (t0->command_bytes_seen == 4) {
                t0->p2 = byte;
            } else if (t0->command_bytes_seen == 5) {
                t0->p3 = byte;
                if (t0_transfer_direction(t0) == PACKET_FROM_CARD) {
                    // This is response length so 0 means 256.
                    // Note that this direction check has false negatives.
                    if (byte == 0x00) {
                        t0->p3_le = 256;
                        t0->state = PROCEDURE_BYTE;
                    } else {
                        t0->p3_le = byte;
                        t0->state = PROCEDURE_BYTE;
                    }
                    t0->p3_lc = 0;
                } else if (t0_transfer_direction(t0) == PACKET_TO_CARD) {
                    t0->p3_lc = byte;
                    t0->p3_le = 0;
                    t0->state = PROCEDURE_BYTE;
                }
                return PACKET_TO_CARD;
            }
            break;
        case PROCEDURE_BYTE:
            if (byte == 0x60) return PACKET_FROM_CARD;
            if ((byte & 0xF0) == 0x60 || (byte & 0xF0) == 0x90 || (byte == 0xCC)) {
                t0->state = SW2;
            } else if (byte == t0->ins) {
                // Expect the remaining bytes, if any
                if (t0->transfer_bytes_seen < t0->p3_lc || t0->transfer_bytes_seen < t0->p3_le) {
                    t0->state = TRANSFER_ALL;
                }
                return PACKET_FROM_CARD;
            } else if ((byte ^ 0xFF) == t0->ins) {
                // Expect a single byte if not all sent already
                if (t0->transfer_bytes_seen < t0->p3_lc || t0->transfer_bytes_seen < t0->p3_le) {
                    t0->state = TRANSFER_ONE;
                }
                return PACKET_FROM_CARD;
            }
            break;
        case SW2:
            // Completion of whole exchange.
            t0->state = COMMAND;
            t0->command_bytes_seen = 0;
            t0->transfer_bytes_seen = 0;
            return PACKET_FROM_CARD;
        case TRANSFER_ALL:
            t0->transfer_bytes_seen++;
            if (t0_transfer_direction(t0) == PACKET_TO_CARD) {
                if (t0->p3_lc == t0->transfer_bytes_seen) {
                    t0->state = PROCEDURE_BYTE;
                    return PACKET_TO_CARD;
                }
            } else if (t0_transfer_direction(t0) == PACKET_FROM_CARD) {
                if (t0->p3_le == t0->transfer_bytes_seen) {
                    t0->state = PROCEDURE_BYTE;
                    return PACKET_FROM_CARD;
                }
            }
            break;
        case TRANSFER_ONE:
            t0->transfer_bytes_seen++;
            t0->state = PROCEDURE_BYTE;
            return t0_transfer_direction(t0);
    }
    return CONTINUE;
}

#define T1_PROLOGUE_LEN (3)

enum result data_t1_analyze(struct data *data, unsigned char byte) {
    struct data_t1 *t1 = &data->t1;
    t1->bytes_seen++;
    if (t1->bytes_seen == T1_PROLOGUE_LEN) {
        t1->msg_length = T1_PROLOGUE_LEN + byte + t1->check_len;
        return CONTINUE;
    }
    if (t1->msg_length && t1->bytes_seen == t1->msg_length) {
        // End of block, reset counters for next block
        enum result res = PACKET_TO_CARD;
        if (t1->direction_from_card) res = PACKET_FROM_CARD;
        t1->bytes_seen = 0;
        t1->msg_length = 0;
        // Flip direction for next packet
        t1->direction_from_card ^= 1;
        return res;
    }
    return CONTINUE;
}

unsigned char gen_lrc(unsigned char *buf, unsigned len) {
    unsigned char lrc = buf[0];
    for (int i=1; i<len; i++) {
        lrc = lrc ^ buf[i];
    }
    return lrc;
}

void generate_iblocks(struct iblocks *blks, unsigned char* apdu, unsigned len, unsigned ifs, unsigned char iN) {
    bcopy(apdu, blks->data_buf, len);
    blks->data_len = len;
    blks->iblock_start = 0;

    unsigned int ilen = len;
    blks->iblock[0] = 0x00;
    blks->iblock[1] = iN;

    if (len > ifs) {
        ilen = ifs;
        blks->iblock[1] = blks->iblock[1] | 0x20;
    }
    blks->iblock[2] = ilen;
    bcopy(blks->data_buf+blks->iblock_start, blks->iblock+3, ilen);
    blks->iblock[ilen + 3] = gen_lrc(blks->iblock, ilen+3);

    blks->iblock_start += ilen;
}

void next_iblock(struct iblocks *blks, unsigned ifs, unsigned char iN) {
    unsigned int ilen = blks->data_len - blks->iblock_start;

    blks->iblock[0] = 0x00;
    blks->iblock[1] = iN;

    if (ilen > ifs) {
        ilen = ifs;
        blks->iblock[1] = blks->iblock[1] | 0x20;
    }
    blks->iblock[2] = ilen;
    bcopy(blks->data_buf+blks->iblock_start, blks->iblock+3, ilen);
    blks->iblock[ilen + 3] = gen_lrc(blks->iblock, ilen+3);

    blks->iblock_start += ilen;
}

void change_iblock_index(struct iblocks *blks, unsigned char iN) {
    unsigned int len = blks->iblock[2];
    if (iN == 0x00) {
        blks->iblock[1] = blks->iblock[1] & 0xBF;
    } else {
        blks->iblock[1] = blks->iblock[1] | 0x40;
    }

    blks->iblock[len + 3] = gen_lrc(blks->iblock, len+3);
}