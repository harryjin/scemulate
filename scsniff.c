#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <termios.h>
#include <fcntl.h>     // open, fcntl
#include <sys/ioctl.h> // ioctl

#include "packet.h"
#include "serial.h"
#include "session.h"
#include "data.h"

static int reset_active(int fd)
{
    int reset = serial_reset_active(fd);
    if (reset == -1)
    {
        fprintf(stderr, "Connection lost\n");
        exit(1);
    }
    return reset;
}

static struct timeval reset_time;
static struct timeval now_time;
static struct timeval atr_time;

static void wait_reset(int fd)
{
    fprintf(stderr, "== Waiting for reset..  ");
    fflush(stderr);
    serial_wait_reset(fd);
    fprintf(stderr, "Done\n");
}

static void usage(char *name)
{
    fprintf(stderr, "\nUsage: %s <device> [<baudrate>]\n", name);
    exit(2);
}

static struct session session;
static int serial;

static bool connected;
static int server_sockfd;
static int sockfd;
socklen_t clilen;

static void send_procedure_byte(char byte)
{
    write(serial, &byte, 1);
    fprintf(stderr, "!");
    char ch;
    int n = 0;
    do
    {
        n = read(serial, &ch, 1);
    } while (n < 1);
    struct timeval diff;
    gettimeofday(&now_time, NULL);
    timersub(&now_time, &reset_time, &diff);

    fprintf(stderr, "+%ld.%06lds-| ", diff.tv_sec, diff.tv_usec);
    fprintf(stderr, "CARD>>>");
    fprintf(stderr, " |");
    fprintf(stderr, " %02X", ch);
    fprintf(stderr, "\n");
}

static int transmit_packet(unsigned char *buf, int len)
{
    unsigned char buffer[512];
    buffer[0] = 'C';
    buffer[1] = 'M';
    buffer[2] = 'D';

    bcopy(buf, buffer + 3, len);
    /* Send message to the server */
    int n = write(sockfd, buffer, len + 3);

    if (n < 0)
    {
        perror("ERROR writing to socket");
    }

    return n;
}

static int receive_packet(unsigned char *buf)
{
    unsigned char buffer[512];

    int n = 0, m = 0;

    for (int i = 0; i < 10; i++)
    {
        /* Now read server response */
        n = read(sockfd, buffer, 512);

        if (n < 0)
        {
            send_procedure_byte(0x60);
        }
        else
        {
            break;
        }
    }

    bcopy(buffer, buf, n);

    if (n < 0)
    {
        perror("ERROR reading from socket");
    }

    return n;
}

static void handle_packet(struct packet *packet)
{
    struct timeval diff;
    unsigned i;
    timersub(&packet->time, &reset_time, &diff);
    fprintf(stderr, "+%ld.%06lds | ", diff.tv_sec, diff.tv_usec);
    switch (packet->result)
    {
    case NOISE:
        fprintf(stderr, "NOISE??");
        break;
    case PACKET_TO_CARD:
        fprintf(stderr, "CARD<<<");
        break;
    case PACKET_FROM_CARD:
        fprintf(stderr, "CARD>>>");
        break;
    case PACKET_UNKNOWN:
        fprintf(stderr, "CARD<?>");
        break;
    default:
        fprintf(stderr, "ERROR!!");
        break;
    }
    fprintf(stderr, " |");
    for (i = 0; i < packet->data_length; i++)
    {
        fprintf(stderr, " %02X", packet->data[i]);
    }
    fprintf(stderr, "\n");

    unsigned char buf[512];
    int buf_len;

    if (session.curr.protocol_version == 0)
    {
        struct data sdata = session.curr.data;
        struct data_t0 t0 = sdata.t0;

        if (packet->result == PACKET_TO_CARD)
        {
            if (t0_transfer_direction(&sdata.t0) == PACKET_TO_CARD)
            {
                if (sdata.t0.state == PROCEDURE_BYTE && sdata.t0.p3_lc > 0)
                {
                    if (t0.p3_lc == t0.transfer_bytes_seen)
                    {
                        buf[0] = sdata.t0.cla;
                        buf[1] = sdata.t0.ins;
                        buf[2] = sdata.t0.p1;
                        buf[3] = sdata.t0.p2;
                        buf[4] = sdata.t0.p3_lc;
                        bcopy(packet->data, buf + 5, packet->data_length);
                        transmit_packet(buf, packet->data_length + 5);
                        buf_len = receive_packet(buf);
                        write(serial, buf, buf_len);
                    }
                    else
                    {
                        unsigned char ins = (unsigned char)session.curr.data.t0.ins;
                        write(serial, &ins, 1);
                    }
                }
                else
                {
                    transmit_packet(packet->data, packet->data_length);
                    buf_len = receive_packet(buf);
                    write(serial, buf, buf_len);
                }
            }
            else if (t0_transfer_direction(&sdata.t0) == PACKET_FROM_CARD)
            {
                if (sdata.t0.state == PROCEDURE_BYTE && sdata.t0.p3_le > 0 && sdata.t0.p3_le < 256)
                {
                    if (t0.p3_le == t0.transfer_bytes_seen)
                    {
                        // transmit_packet(packet->data, packet->data_length);
                    }
                    else
                    {
                        transmit_packet(packet->data, packet->data_length);
                        buf_len = receive_packet(buf);

                        unsigned char ins = (unsigned char)session.curr.data.t0.ins;
                        write(serial, &ins, 1);
                        write(serial, buf, buf_len);
                    }
                }
                else
                {
                    transmit_packet(packet->data, packet->data_length);
                    buf_len = receive_packet(buf);
                    write(serial, buf, buf_len);
                }
            }
        }
        else if (packet->result == PACKET_FROM_CARD)
        {
            if (sdata.t0.state == TRANSFER_ALL || sdata.t0.state == TRANSFER_ONE)
            {
                if (t0_transfer_direction(&sdata.t0) == PACKET_FROM_CARD)
                {
                }
            }
        }
    }
    else if (session.curr.protocol_version == 1)
    {
        if (packet->result == PACKET_TO_CARD)
        {
            if ((packet->data[1] & 0x80) == 0x00)
            {
                transmit_packet(packet->data, packet->data_length);
                buf_len = receive_packet(buf);

                generate_iblocks(&session.curr.blks_from_card, buf, buf_len, session.curr.ifs, packet->data[1] & 0x40);
                write(serial, session.curr.blks_from_card.iblock, session.curr.blks_from_card.iblock[2] + 4);
            }
            else if ((packet->data[1] & 0xC0) == 0x80)
            {
                if ((packet->data[1] & 0x0F) == 0x00)
                {
                    if ((packet->data[1] & 0x1F) == 0x00)
                    {
                        next_iblock(&session.curr.blks_from_card, session.curr.ifs, 0x00);
                    }
                    else
                    {
                        next_iblock(&session.curr.blks_from_card, session.curr.ifs, 0x40);
                    }
                    write(serial, session.curr.blks_from_card.iblock, session.curr.blks_from_card.iblock[2] + 4);
                }
                else if ((packet->data[1] & 0x0F) == 0x02)
                {
                    if ((packet->data[1] & 0x10) == 0x00)
                    {
                        change_iblock_index(&session.curr.blks_from_card, 0x00);
                    }
                    else
                    {
                        change_iblock_index(&session.curr.blks_from_card, 0x40);
                    }
                    write(serial, session.curr.blks_from_card.iblock, session.curr.blks_from_card.iblock[2] + 4);
                }
            }
            else if (packet->data[1] == 0xC1)
            {
                session.curr.ifs = packet->data[3];

                buf_len = packet->data_length;
                bcopy(packet->data, buf, packet->data_length);

                buf[1] = 0xE1;
                buf[buf_len - 1] = gen_lrc(buf, buf_len - 1);
                write(serial, buf, buf_len);
            }
        }
    }
}

static void log_message(const char *message)
{
    fprintf(stderr, "== %s\n", message);
}

int main(int argc, char **argv)
{
    int portno, n;
    struct sockaddr_in serv_addr, cli_addr;

    char buffer[256];

    if (argc < 3)
        usage(argv[0]);
    int fd = serial_open(argv[1]);
    if (fd < 0)
    {
        fprintf(stderr, "Opening %s ", argv[1]);
        perror("failed");
        usage(argv[0]);
    }
    int baudrate = 9600;
    if (argc > 2)
    {
        baudrate = atoi(argv[2]);
    }
    if (baudrate <= 0)
    {
        fprintf(stderr, "Failed to parse baudrate '%s'\n", argv[2]);
        usage(argv[0]);
    }
    fprintf(stderr, "== Opened %s\n", argv[1]);

    portno = 27015;

    /* Create a socket point */
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(1);
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(server_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR on binding");
        exit(2);
    }

    listen(server_sockfd, 5);

    while (1)
    {
        connected = false;
        clilen = sizeof(cli_addr);
        sockfd = accept(server_sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (sockfd < 0)
        {
            perror("ERROR - accept socket\n");
            continue;
        }

        connected = true;
        /* Now ask for a message from the user, this message
         * will be read by server
         */
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 600000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));

        fprintf(stderr, "Connected Bridge\n");

        bzero(buffer, 256);
    
        fprintf(stderr, "Waiting ATR for Smart Card ...\n");

        char *CMDATR = "ATR";
        unsigned char atr[256], atr_len = 0;
        bzero(atr, 256);

        while(1) {
            n = recv(sockfd, buffer, 255, 0);

            if (n > 0) {
                if (strncmp(buffer, CMDATR, 3) == 0) {
                    bcopy(buffer + 3, atr, n);
                    atr_len = n - 3;
                    break;
                }
            }

            if (n == 0) {
                connected = false;
                break;
            }
        }

        if (atr_len == 0) {
            continue;
        }
        // unsigned char ATR[] = { 0x3B, 0x6F, 0x00, 0x00, 0x00, 0xB8, 0x54, 0x31, 0x10, 0x07, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        fprintf(stderr, "Received ATR %d\n", n);
        for (int i = 0; i < n; i++)
            fprintf(stderr, "%02x ", atr[i]);
        fprintf(stderr, "\n");

        session_init(&session, handle_packet, serial_configure, log_message,
                     fd, baudrate);
        serial = fd;
        int atr_flag = 0;
        while (1)
        {
            unsigned char atr_index = 0;
            atr_flag = 0;

            fprintf(stderr, "== Speed: %d baud\n", baudrate);
            if (!reset_active(fd))
                wait_reset(fd);
            gettimeofday(&reset_time, NULL);
            while (reset_active(fd))
            {
                // Eat noise while reset active.
                unsigned char c;
                read(fd, &c, 1);
            }

            struct timeval diff;
            gettimeofday(&now_time, NULL);
            timersub(&now_time, &reset_time, &diff);

            if (diff.tv_usec > 600)
            {
                atr_flag = 1;
            }

            int loops = 0;
            int resets = 0;
            while (1)
            {
                unsigned char c;
                if (atr_flag == 1)
                {
                    if (atr_index < atr_len)
                    {
                        write(fd, atr + atr_index, 1);
                        gettimeofday(&atr_time, NULL);
                        atr_flag = 2;
                    }
                    else
                    {
                        atr_flag = 3;
                    }
                }
                else if (atr_flag == 2)
                {
                    gettimeofday(&now_time, NULL);
                    timersub(&now_time, &atr_time, &diff);

                    if (diff.tv_usec > 1000)
                    {
                        atr_index++;
                        atr_flag = 1;
                    }
                }

                if (read(fd, &c, 1) > 0)
                {
                    loops = 0;
                    if (resets < 15)
                    {
                        session_add_byte(&session, c);
                    }
                }
                if (reset_active(fd))
                {
                    resets++;
                    if (resets > 50)
                    {
                        gettimeofday(&now_time, NULL);
                        timersub(&now_time, &reset_time, &diff);
                        fprintf(stderr, "+%ld.%06lds | ", diff.tv_sec, diff.tv_usec);
                        fprintf(stderr, "\n========================="
                                        "\n== Got warm reset or deactivate\n");
                        break;
                    }
                }
                else
                {
                    resets = 0;
                }
                loops++;
                if (loops > 3000000)
                {
                    fprintf(stderr, "\n=========================\n== Timeout!\n");
                    break;
                }

                int err = 0;
                socklen_t size = sizeof (err);
                int check = getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &err, &size);
                if (check != 0) {
                    fprintf(stderr, "\nConnection Error - 1!\n");
                    break;
                }
            }

            session_reset(&session);

            int err = 0;
            socklen_t size = sizeof (err);
            int check = getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &err, &size);
            if (check != 0) {
                fprintf(stderr, "\nConnection Error - 2!\n");
                break;
            }            
        }
    }

    return 0;
}
