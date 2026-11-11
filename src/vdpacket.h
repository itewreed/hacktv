/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Channel VideoDat packet encoder, ported from raspi-teletext            */
/* (https://github.com/itewreed/raspi-teletext, vdpacket.c)              */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#ifndef _VDPACKET_H
#define _VDPACKET_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define VD_SYNC0 (0x56)
#define VD_SYNC1 (0xAE)
#define VD_KEY_XOR (0x58)

/* Largest payload sent by this encoder (2^8). All packets seen in
 * recordings are this size or smaller. */
#define VD_MAX_LOG2 (8)
#define VD_MAX_PAYLOAD (1 << VD_MAX_LOG2)

/* 9 header bytes, payload, 2 checksum bytes, plus room for the 0xFF
 * escape bytes inserted after every 56 AE inside a packet. */
#define VD_MAX_PACKET ((VD_MAX_PAYLOAD + 11) * 3 / 2)

/* Packets are sent in groups of this many, and each group is repeated */
#define VD_GROUP (4)

/* Payload types (first payload byte) used for file transfer */
#define VD_TYPE_INFO   (0x00)
#define VD_TYPE_HEADER (0x02)
#define VD_TYPE_END    (0x03)
#define VD_TYPE_DATA   (0x04)
#define VD_TYPE_CLOCK  (0x06)

/* Data block size of file transfer (payload size minus the type byte) */
#define VD_BLOCK (VD_MAX_PAYLOAD - 1)

typedef void (*vd_emit_func_t)(const uint8_t *data, size_t len, void *ctx);

typedef struct {
	vd_emit_func_t emit;
	void *ctx;
	uint32_t rng;       /* State of the generator for the scrambling parameters */
	int repeat;         /* How often each group of packets is sent */
	
	/* Called before each group is sent, eg to slip in a clock packet */
	void (*hook)(void *ctx);
	int in_hook;
	
	/* Time put into file headers, end packets and info blocks.
	 * NULL means the current time. */
	time_t (*now)(void *ctx);
} vd_tx_t;

typedef struct {
	vd_tx_t *tx;
	uint8_t A;          /* Data stream number */
	uint8_t sub;        /* Sub channel (bit 7 of B) */
	uint8_t C;          /* Packet counter of the next packet */
	
	/* Groups are counted in bits 4..6 of B as ((C + phase) >> 2) & 7.
	 * Recordings have phase 1 on file streams, so the first group of a
	 * stream is C 0..2, and phase 0 on stream 01. */
	int phase;
	int repeat;         /* How often each group is sent */
	int queued;
	uint8_t payload[VD_GROUP][VD_MAX_PAYLOAD];
	uint8_t log2[VD_GROUP];
} vd_stream_t;

/* Build one packet. payload holds 2^(B & 15) bytes of clear data. Writes
 * sync, header, scrambled payload and checksum to out, with 0xFF inserted
 * after each 56 AE following the sync word, and returns the length. */
extern size_t vd_build_packet(uint8_t *out, uint8_t A, uint8_t B, uint8_t C, const uint8_t *payload, uint8_t D, uint8_t E, uint8_t F, uint8_t S);

extern void vd_tx_init(vd_tx_t *tx, vd_emit_func_t emit, void *ctx, uint32_t seed, int repeat);
extern void vd_stream_init(vd_stream_t *s, vd_tx_t *tx, uint8_t A, int sub);

/* Queue a payload of up to VD_MAX_PAYLOAD bytes. It is padded with zeros
 * to the next power of two. A full group is sent at once. */
extern int vd_send(vd_stream_t *s, const uint8_t *payload, size_t len);

/* Send the queued packets as a (short) group */
extern void vd_flush(vd_stream_t *s);

/* MS-DOS date and time (date in the high word), as used in file headers */
extern uint32_t vd_dos_time(time_t t);

extern int vd_send_file(vd_stream_t *s, const char *name, const uint8_t *data, uint32_t size, time_t mtime);

/* Clock on stream 01, sent once (not repeated) and at once */
extern void vd_clock_init(vd_stream_t *s, vd_tx_t *tx);
extern void vd_send_clock(vd_stream_t *s, time_t now);
extern void vd_send_info(vd_stream_t *s, const char *text, int count);

#endif

