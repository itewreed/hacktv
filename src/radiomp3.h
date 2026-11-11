/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* r@dio.mp3 / MEGARADIO.mp3 output, ported from raspi-teletext's rmenc */
/* (https://github.com/itewreed/raspi-teletext)                          */
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

#ifndef _RADIOMP3_H
#define _RADIOMP3_H

#include <stdint.h>
#include "video.h"
#include "vbidata.h"

/* The most streams and files that can be sent together */
#define RM_MAX_SOURCES (64)

/* Teletext packets of one superblock: 15 pages of 24 packets */
#define RM_ROW_SIZE (896)
#define RM_ROWS (15)
#define RM_PACKETS_PER_PAGE (24)
#define RM_PACKETS (RM_ROWS * RM_PACKETS_PER_PAGE)

/* Bit n of a line mask is line 7 + n (first field) or 320 + n
 * (second field). Alone, r@dio.mp3 uses all 16 lines per field;
 * with --teletext the default leaves lines 15-22 and 328-335 free
 * for the teletext service. */
#define RM_DEFAULT_MASK (0xFFFF)
#define RM_DEFAULT_MASK_SHARED (0x00FF)

/* Size of the buffer for a live stream from stdin */
#define RM_LIVE_BUFFER (256 * 1024)

typedef struct {
	const char *path;
	int stream;		/* 1 = live stream, 0 = file */
	int live;		/* Read from stdin as it comes */
	uint16_t id;
	uint8_t info[24];
	uint8_t *data;		/* The whole file, or the live buffer */
	uint32_t size;		/* File size, or bytes in the live buffer */
	uint32_t pos;		/* Read position in data */
	uint32_t offset;	/* Offset sent in the row header */
	int eof;		/* Live stream: stdin has ended */
	int done;
} rm_source_t;

typedef struct {
	vid_t *vid;
	vbidata_lut_t *lut;
	uint16_t mask[2];
	int loop;

	rm_source_t sources[RM_MAX_SOURCES];
	int nsources;
	int next_source;
	int live;		/* Index of the live source, or -1 */
	int finished;

	/* The packets of the current superblock, as VBI lines */
	uint8_t packets[RM_PACKETS][45];
	int npackets;
	int packet;
	int superblocks;

	uint8_t rows[RM_ROWS][RM_ROW_SIZE];

} radiomp3_t;

extern int radiomp3_init(radiomp3_t *s, vid_t *vid, int nsources, const char *const *sources, const int *streams, int loop, const char *lines, int shared);
extern void radiomp3_free(radiomp3_t *s);
extern int radiomp3_render(vid_t *s, void *arg, int nlines, vid_line_t **lines);

#endif

