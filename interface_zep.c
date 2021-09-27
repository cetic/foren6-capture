/*
 * This file is part of Foren6, a 6LoWPAN Diagnosis Tool
 * Copyright (C) 2013, CETIC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * \file
 *         ZEP input interface
 * \author
 *         Benjamin Valentin <benjamin.valentin@ml-pa.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "interface_zep.h"

#if __APPLE__
#define pthread_timedjoin_np(...) (1)
#endif

#ifndef ZEP_PDU
#define ZEP_PDU 255
#endif

enum {
    ZEP_V2_TYPE_DATA  = 1,   /**< IEEE 802.15.4 data frame */
    ZEP_V2_TYPE_ACK   = 2,   /**< IEEE 802.15.4 ACK frame */
    ZEP_V2_TYPE_HELLO = 255, /**< custom type to register with ZEP dispatcher */
};

/**
 * @brief A 16 bit integer in network byte order.
 */
typedef uint16_t network_uint16_t;

/**
 * @brief A 32 bit integer in network byte order.
 */
typedef uint32_t network_uint32_t;

/**
 * @brief NTP timestamp
 *
 * @see   [RFC 5905, Section 6](https://tools.ietf.org/html/rfc5905#section-6)
 */
typedef struct __attribute__((packed)) {
    network_uint32_t seconds;           /**< seconds since 1 January 1900 00:00 UTC */
    network_uint32_t fraction;          /**< fraction of seconds in 232 picoseconds */
} ntp_timestamp_t;

/**
 * @brief   ZEPv2 header definition (type == Data)
 */
typedef struct __attribute__((packed)) {
    char preamble[2];       /**< Preamble code (must be "EX") */
    uint8_t version;        /**< Protocol Version (must be 1 or 2) */
    uint8_t type;           /**< type (must be @ref ZEP_V2_TYPE_DATA) */
    uint8_t chan;           /**< channel ID */
    network_uint16_t dev;   /**< device ID */
    uint8_t lqi_mode;       /**< CRC/LQI Mode */
    uint8_t lqi_val;        /**< LQI value */
    ntp_timestamp_t time;   /**< NTP timestamp */
    network_uint32_t seq;   /**< Sequence number */
    uint8_t resv[10];       /**< reserved field, must always be 0 */
    uint8_t length;         /**< length of the frame */
} zep_v2_data_hdr_t;

static const char *ZEP_default_host = "[::1]";
static const char *ZEP_default_port = "17754";

typedef struct {
    ifinstance_t *instance;
    struct addrinfo *ai;
    int sock;
    pthread_t thread;
    bool capture_packets;
    struct timeval start_time;
} interface_handle_t;

static void *
zep_get_payload(const void *buffer, size_t len, size_t *len_data)
{
    const void *payload;
    const zep_v2_data_hdr_t *zep = buffer;

    switch (zep->type) {
    case ZEP_V2_TYPE_DATA:
        *len_data = zep->length;
        return (zep_v2_data_hdr_t *)zep + 1;
    default:
        *len_data = 0;
        return NULL;
    }
}

static void *
interface_thread_process_input(void *data)
{
    ifreader_t handle = data;
    interface_handle_t *descriptor = (interface_handle_t *) handle->interface_data;

    /* dummy packet */
    zep_v2_data_hdr_t hdr = {
        .preamble = "EX",
        .version  = 2,
        .type = ZEP_V2_TYPE_HELLO,
        .resv = "HELLO",
        .length = 0,
    };

    /* send HELLO */
    send(descriptor->sock, &hdr, sizeof(hdr), 0);

    while (1) {
        uint8_t buffer[ZEP_PDU];
        struct sockaddr_in6 src_addr;
        socklen_t addr_len = sizeof(src_addr);

        /* receive incoming packet */
        ssize_t bytes_in = recvfrom(descriptor->sock, buffer, sizeof(buffer), 0,
                                    (struct sockaddr *)&src_addr, &addr_len);

        if (bytes_in <= 0 || addr_len != sizeof(src_addr)) {
            continue;
        }

        size_t len_data;
        void *payload = zep_get_payload(buffer, bytes_in, &len_data);

        if (len_data == 0) {
            continue;
        }

        struct timeval pkt_time;
        gettimeofday(&pkt_time, NULL);
        if (pkt_time.tv_usec < descriptor->start_time.tv_usec) {
            pkt_time.tv_sec = pkt_time.tv_sec
                    - descriptor->start_time.tv_sec - 1;
            pkt_time.tv_usec = pkt_time.tv_usec + 1000000
                    - descriptor->start_time.tv_usec;
        } else {
            pkt_time.tv_sec = pkt_time.tv_sec
                    - descriptor->start_time.tv_sec;
            pkt_time.tv_usec = pkt_time.tv_usec
                    - descriptor->start_time.tv_usec;
        }

        interfacemgr_process_packet(handle, payload, len_data, pkt_time);
    }
}

int
interface_get_version()
{
    return 1;
}

static void
interface_init()
{
    fprintf(stderr, "ZEP interface initialized\n");
}

static bool
_parse_uri(const char *target, char **_host, const char **_port)
{
    char *host = NULL;
    const char *port = NULL;

    if (strlen(target) == 0) {
        target = ZEP_default_host;
    }

    const char *addr = strchr(target, '[');
    if (addr) {
        ++addr;
        const char *end = strchr(addr, ']');
        if (end == NULL) {
            return false;
        }

        host = strndup(addr, end - addr);
        target = end;
    }

    port = strchr(target, ':');
    if (port) {
        if (host == NULL) {
            host = strndup(target, port - target);
        }

        ++port;
    } else if (host == NULL) {
        host = strdup(target);
    }

    if (port == NULL) {
        port = ZEP_default_port;
    }

    if (!atoi(port)) {
        return false;
    }

    *_host = host;
    *_port = port;

    return true;
}

static ifreader_t
interface_open(const char *target, int channel, int baudrate)
{
    int res;

    interface_handle_t *handle;
    char *server;
    const char *port;


    handle = (interface_handle_t *) calloc(1, sizeof(interface_handle_t));
    if (!handle) {
        return NULL;
    }

    if (!_parse_uri(target, &server, &port)) {
        fprintf(stderr, "ZEP: invalid URI: %s\n", target);
        return false;
    }

    fprintf(stderr, "ZEP dispatcher on %s, port %s\n", server, port);

    static const struct addrinfo hints = { .ai_family = AF_UNSPEC,
                                           .ai_socktype = SOCK_DGRAM };

    if ((res = getaddrinfo(server, port, &hints, &handle->ai)) < 0) {
        fprintf(stderr, "ZEP: unable to get remote address: %s\n",
                strerror(res));
        return false;
    }

    ifreader_t ifinstance = interfacemgr_create_handle(target);
    ifinstance->interface_data = handle;

    free(server);

    return ifinstance;
}

static bool
interface_start(ifreader_t handle)
{
    struct addrinfo *remote;
    interface_handle_t *descriptor = (interface_handle_t *) handle->interface_data;

    if (descriptor->capture_packets) {
        return true;
    }

    descriptor->sock = socket(AF_INET6, SOCK_DGRAM, 0);
    for (remote = descriptor->ai; remote != NULL; remote = remote->ai_next) {
        if (connect(descriptor->sock, remote->ai_addr, remote->ai_addrlen) == 0) {
            break;  /* successfully connected */
        }
    }

    if (remote == NULL) {
        fprintf(stderr, "ZEP: Unable to connect socket\n");
        return false;
    }

    gettimeofday(&descriptor->start_time, NULL);
    descriptor->capture_packets = true;
    pthread_create(&descriptor->thread, NULL,
                   &interface_thread_process_input, handle);
    return true;
}

static void
interface_stop(ifreader_t handle)
{
    const struct timespec timeout = { 3, 0 };
    interface_handle_t *descriptor = (interface_handle_t *) handle->interface_data;

    if (!descriptor->capture_packets) {
        return;
    }

    if (pthread_timedjoin_np(descriptor->thread, NULL, &timeout) != 0) {
        pthread_cancel(descriptor->thread);
        pthread_join(descriptor->thread, NULL);
    }

    descriptor->capture_packets = false;
}

static void
interface_close(ifreader_t handle)
{
    interface_handle_t *descriptor = (interface_handle_t *) handle->interface_data;

    interface_stop(handle);

    close(descriptor->sock);

    freeaddrinfo(descriptor->ai);

    free(descriptor);

    interfacemgr_destroy_handle(handle);
}

interface_t
interface_register()
{
    interface_t interface;

    memset(&interface, 0, sizeof(interface));

    interface.interface_name = "zep";
    interface.parameters = INTERFACE_TARGET;
    interface.init = interface_init;
    interface.open = interface_open;
    interface.close = interface_close;
    interface.start = interface_start;
    interface.stop = interface_stop;

    return interface;
}
