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

/* r@dio.mp3 (2000-2001) and MEGARADIO.mp3 (2002-2003) sent MP3 music,
 * covers and HTML pages in the VBI of NBC Europe, as teletext packets in
 * magazine 8 ("TV Radio Cast" by RapidSolution). The format, reconstructed
 * from the Megaradio.mp3 1.2.0.6 player, is described in
 * https://github.com/itewreed/radiomp3-decoder (docs/FORMAT.md), and
 * radiomp3-decoder turns a capture of it back into files. Sent once
 * (--radiomp3-once), the packets are the same, byte for byte, as those of
 * raspi-teletext's rmenc and "radiomp3 testsignal".
 *
 * Layers, from the top:
 *
 * Data row, 896 bytes:
 *     0..9    header, every byte XORed with 0xA5: id (u16), offset (u32),
 *             total length (u32), all little endian
 *     10..13  Adler-32 of the row with these 4 bytes zero (little endian)
 *     stream rows (id a multiple of 10, not 0 or 100): payload at 16, up
 *             to 880 bytes
 *     file rows (any other id): 24 bytes of file info (the name) at 14,
 *             payload at 38, up to 858 bytes
 *     id 100 is a filler row.
 *
 * Superblock: 13 data rows and 2 parity rows. Column c (0..63) is bytes
 * c*14 .. c*14+13 of each data row, 182 bytes, protected by 28 Reed-Solomon
 * parity bytes (GF(256), polynomial 0x11D, roots alpha^1..alpha^28) at
 * c*28 in the 1792 bytes of the two parity rows.
 *
 * Page: each of the 15 rows goes out as one page in magazine 8, packets 0
 * to 23. Packet 0 is a page header, packet 1 carries H(row 1..15), H(aux)
 * and 38 bytes, packets 2..23 H(row) and 39 bytes each (H = Hamming 8/4).
 * aux counts the superblocks, 1..15.
 *
 * The packets go out on their own VBI lines, picked with a line mask like
 * Channel VideoDat. They are rendered like hacktv's teletext.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include "video.h"
#include "radiomp3.h"

#define _DATA_ROWS (13)
#define _COLUMNS (64)
#define _COLUMN_WIDTH (14)
#define _NPAR (28)
#define _STREAM_PAYLOAD (880)
#define _FILE_PAYLOAD (858)
#define _INFO_SIZE (24)
#define _FILLER_ID (100)
#define _MAGAZINE (0)		/* Magazine 8, as coded in the MRAG */
#define _LAST_PACKET (23)
#define _P1_PAYLOAD (38)
#define _PN_PAYLOAD (39)

/* next_row() results */
#define _ROW_OK (1)
#define _ROW_DONE (0)
#define _ROW_WAIT (2)



/* ---- Reed-Solomon, as Henry Minsky's rscode in the original player ---- */

static uint8_t _gf_exp[512];
static uint8_t _gf_log[256];
static uint8_t _genpoly[_NPAR + 1];	/* _genpoly[0] is the highest power */

static uint8_t _gf_mul(uint8_t a, uint8_t b)
{
	return((a && b) ? _gf_exp[_gf_log[a] + _gf_log[b]] : 0);
}

static void _rs_init(void)
{
	int i, j, len, x = 1;

	for(i = 0; i < 255; i++)
	{
		_gf_exp[i] = x;
		_gf_log[x] = i;
		x <<= 1;
		if(x & 0x100) x ^= 0x11D;
	}

	for(i = 255; i < 512; i++)
	{
		_gf_exp[i] = _gf_exp[i - 255];
	}

	/* Product of (x + alpha^i) for i = 1..28 */
	len = 1;
	_genpoly[0] = 1;

	for(i = 1; i <= _NPAR; i++)
	{
		uint8_t root = _gf_exp[i];

		_genpoly[len] = 0;

		for(j = len; j > 0; j--)
		{
			_genpoly[j] ^= _gf_mul(_genpoly[j - 1], root);
		}

		len++;
	}
}

/* parity = msg * x^28 mod genpoly */
static void _rs_encode(const uint8_t *msg, int n, uint8_t *parity)
{
	uint8_t buf[256 + _NPAR];
	int i, j;

	memcpy(buf, msg, n);
	memset(buf + n, 0, _NPAR);

	for(i = 0; i < n; i++)
	{
		uint8_t coef = buf[i];

		if(coef == 0) continue;

		for(j = 1; j <= _NPAR; j++)
		{
			buf[i + j] ^= _gf_mul(coef, _genpoly[j]);
		}
	}

	memcpy(parity, buf + n, _NPAR);
}



/* ---- Hamming 8/4 ---- */

static uint8_t _hamming84(int d)
{
	int d1 = (d >> 0) & 1;
	int d2 = (d >> 1) & 1;
	int d3 = (d >> 2) & 1;
	int d4 = (d >> 3) & 1;
	int p1 = 1 ^ d1 ^ d3 ^ d4;
	int p2 = 1 ^ d1 ^ d2 ^ d4;
	int p3 = 1 ^ d1 ^ d2 ^ d3;
	int p4 = 1 ^ p1 ^ d1 ^ p2 ^ d2 ^ p3 ^ d3 ^ d4;

	return(p1 | (d1 << 1) | (p2 << 2) | (d2 << 3) | (p3 << 4) | (d3 << 5) | (p4 << 6) | (d4 << 7));
}



/* ---- Data rows ---- */

static uint32_t _adler32(const uint8_t *p, size_t n)
{
	uint32_t a = 1, b = 0;

	while(n--)
	{
		a = (a + *p++) % 65521;
		b = (b + a) % 65521;
	}

	return((b << 16) | a);
}

static void _put_le(uint8_t *p, uint32_t v, int n)
{
	while(n--)
	{
		*p++ = v & 0xFF;
		v >>= 8;
	}
}

static void _build_row(uint8_t *row, int stream, uint16_t id, uint32_t offset, uint32_t total, const uint8_t *data, size_t len, const uint8_t *info)
{
	int i;

	memset(row, 0, RM_ROW_SIZE);
	_put_le(row, id, 2);
	_put_le(row + 2, offset, 4);
	_put_le(row + 6, total, 4);

	if(stream)
	{
		if(len) memcpy(row + 16, data, len);
	}
	else
	{
		memcpy(row + 14, info, _INFO_SIZE);
		if(len) memcpy(row + 38, data, len);
	}

	for(i = 0; i < 10; i++)
	{
		row[i] ^= 0xA5;
	}

	/* The checksum covers the obfuscated header, as on air */
	_put_le(row + 10, _adler32(row, RM_ROW_SIZE), 4);
}



/* ---- Sources: streams and files, sent round robin ---- */

static int _load(rm_source_t *src)
{
	FILE *f;
	size_t cap = 65536, n = 0, r;
	uint8_t *d;

	f = fopen(src->path, "rb");
	if(!f)
	{
		fprintf(stderr, "radiomp3: %s: %s\n", src->path, strerror(errno));
		return(VID_ERROR);
	}

	src->data = malloc(cap);

	while(src->data && (r = fread(src->data + n, 1, cap - n, f)) > 0)
	{
		n += r;

		if(n == cap)
		{
			d = realloc(src->data, cap *= 2);
			if(!d) free(src->data);
			src->data = d;
		}
	}

	if(!src->data || ferror(f))
	{
		fprintf(stderr, "radiomp3: %s: Read error\n", src->path);
		fclose(f);
		return(VID_ERROR);
	}

	fclose(f);

	if(n > 0xFFFFFFFFu - _STREAM_PAYLOAD)
	{
		fprintf(stderr, "radiomp3: %s: Too big\n", src->path);
		return(VID_ERROR);
	}

	src->size = n;

	return(VID_OK);
}

/* Reads what stdin has for the live stream, without waiting */
static void _fill_live(rm_source_t *src)
{
	ssize_t r;

	if(src->pos > 0)
	{
		memmove(src->data, src->data + src->pos, src->size - src->pos);
		src->size -= src->pos;
		src->pos = 0;
	}

	while(!src->eof && src->size < RM_LIVE_BUFFER)
	{
		r = read(STDIN_FILENO, src->data + src->size, RM_LIVE_BUFFER - src->size);

		if(r > 0)
		{
			src->size += r;
		}
		else if(r == 0)
		{
			src->eof = 1;
		}
		else if(errno == EINTR)
		{
			continue;
		}
		else
		{
			/* EAGAIN: nothing there yet */
			break;
		}
	}
}

/* Makes the next row of a source */
static int _next_row(radiomp3_t *s, rm_source_t *src, uint8_t *row)
{
	size_t n, max;
	uint32_t total;

	if(src->done)
	{
		return(_ROW_DONE);
	}

	if(src->live)
	{
		/* Wait for a full row unless the stream has ended. The total
		 * of a stream whose length isn't known yet is a running mark:
		 * the end of this row's data. */
		n = src->size - src->pos;

		if(n < _STREAM_PAYLOAD && !src->eof)
		{
			_fill_live(src);
			n = src->size - src->pos;
		}

		if(n == 0 && src->eof)
		{
			src->done = 1;
			return(_ROW_DONE);
		}

		if(n < _STREAM_PAYLOAD && !src->eof)
		{
			return(_ROW_WAIT);
		}

		if(n > _STREAM_PAYLOAD) n = _STREAM_PAYLOAD;

		_build_row(row, 1, src->id, src->offset, src->offset + n, src->data + src->pos, n, NULL);
		src->pos += n;
		src->offset += n;

		return(_ROW_OK);
	}

	if(src->pos >= src->size)
	{
		if(!s->loop || src->size == 0)
		{
			src->done = 1;
			return(_ROW_DONE);
		}

		src->pos = 0;

		/* Files start again at offset 0, the decoder drops the copies
		 * it already has. Streams run on, so that the decoder writes
		 * one continuous MP3 file. */
		if(!src->stream)
		{
			src->offset = 0;
		}
	}

	max = src->stream ? _STREAM_PAYLOAD : _FILE_PAYLOAD;
	n = src->size - src->pos;
	if(n > max) n = max;

	/* A looped stream has no end either, so it also uses a running mark */
	total = (src->stream && s->loop) ? src->offset + n : src->size;

	_build_row(row, src->stream, src->id, src->offset, total, src->data + src->pos, n, src->info);
	src->pos += n;
	src->offset += n;

	return(_ROW_OK);
}



/* ---- Pages ---- */

static uint8_t *_packet(radiomp3_t *s, int packet)
{
	uint8_t *p = s->packets[s->npackets++];
	int v = (_MAGAZINE & 7) | (packet << 3);

	/* Clock run-in and framing code */
	p[0] = 0x55;
	p[1] = 0x55;
	p[2] = 0x27;

	/* MRAG */
	p[3] = _hamming84(v & 0xF);
	p[4] = _hamming84(v >> 4);

	return(p + 3);
}

static void _page(radiomp3_t *s, int row_index, const uint8_t *data, int aux)
{
	uint8_t *pk;
	int i, n;

	/* Header: page number, subcode and control bits all 0, no text */
	pk = _packet(s, 0);
	for(i = 2; i < 10; i++)
	{
		pk[i] = _hamming84(0);
	}
	memset(pk + 10, ' ', 32);

	pk = _packet(s, 1);
	pk[2] = _hamming84(row_index);
	pk[3] = _hamming84(aux);
	memcpy(pk + 4, data, _P1_PAYLOAD);
	data += _P1_PAYLOAD;

	for(n = 2; n <= _LAST_PACKET; n++, data += _PN_PAYLOAD)
	{
		pk = _packet(s, n);
		pk[2] = _hamming84(row_index);
		memcpy(pk + 3, data, _PN_PAYLOAD);
	}
}

static void _superblock(radiomp3_t *s)
{
	uint8_t msg[_DATA_ROWS * _COLUMN_WIDTH];
	uint8_t *parity = s->rows[_DATA_ROWS];
	int c, r, aux;

	/* Parity rows 14 and 15, one RS codeword per column */
	for(c = 0; c < _COLUMNS; c++)
	{
		for(r = 0; r < _DATA_ROWS; r++)
		{
			memcpy(msg + r * _COLUMN_WIDTH, s->rows[r] + c * _COLUMN_WIDTH, _COLUMN_WIDTH);
		}

		_rs_encode(msg, sizeof(msg), parity + c * _NPAR);
	}

	aux = s->superblocks++ % 15 + 1;

	s->npackets = 0;
	s->packet = 0;

	for(r = 0; r < RM_ROWS; r++)
	{
		_page(s, r + 1, s->rows[r], aux);
	}
}

/* Fills the next superblock. Returns 0 when there is nothing left to send. */
static int _next_superblock(radiomp3_t *s)
{
	int rows = 0;
	int idle = 0;
	int r;

	if(s->finished)
	{
		return(0);
	}

	/* Round robin over the sources, one row each, as rmenc does */
	while(rows < _DATA_ROWS)
	{
		rm_source_t *src;

		/* A live broadcast ends with its stream */
		if(s->live >= 0 && s->sources[s->live].done)
		{
			break;
		}

		/* Stop when a whole round brought nothing */
		if(idle == s->nsources)
		{
			break;
		}

		src = &s->sources[s->next_source];
		s->next_source = (s->next_source + 1) % s->nsources;

		r = _next_row(s, src, s->rows[rows]);

		if(r == _ROW_OK)
		{
			rows++;
			idle = 0;
		}
		else
		{
			idle++;
		}
	}

	if(rows == 0)
	{
		int active = 0;

		for(r = 0; r < s->nsources; r++)
		{
			if(!s->sources[r].done) active = 1;
		}

		if(!active || (s->live >= 0 && s->sources[s->live].done))
		{
			/* Everything has been sent */
			s->finished = 1;
			fprintf(stderr, "radiomp3: Finished after %d superblocks.\n", s->superblocks);
			return(0);
		}
	}

	/* A live stream that isn't ready yet, or the end of the data:
	 * fill the rest of the superblock with filler rows */
	while(rows < _DATA_ROWS)
	{
		_build_row(s->rows[rows++], 1, _FILLER_ID, 0, 0, NULL, 0, NULL);
	}

	_superblock(s);

	return(1);
}



/* ---- Setup ---- */

static int _parse_lines(radiomp3_t *s, const char *lines, int shared)
{
	char *end;
	long m;

	s->mask[0] = s->mask[1] = shared ? RM_DEFAULT_MASK_SHARED : RM_DEFAULT_MASK;

	if(lines == NULL)
	{
		return(VID_OK);
	}

	/* <mask>[,<mask>], the first for field 1, the second for field 2 */
	m = strtol(lines, &end, 0);
	if(end == lines || m < 0 || m > 0xFFFF || (*end != '\0' && *end != ','))
	{
		fprintf(stderr, "radiomp3: Invalid line mask '%s'\n", lines);
		return(VID_ERROR);
	}

	s->mask[0] = s->mask[1] = m;

	if(*end == ',')
	{
		const char *p = end + 1;

		m = strtol(p, &end, 0);
		if(end == p || m < 0 || m > 0xFFFF || *end != '\0')
		{
			fprintf(stderr, "radiomp3: Invalid line mask '%s'\n", lines);
			return(VID_ERROR);
		}

		s->mask[1] = m;
	}

	if(s->mask[0] == 0 && s->mask[1] == 0)
	{
		fprintf(stderr, "radiomp3: The line masks select no lines\n");
		return(VID_ERROR);
	}

	return(VID_OK);
}

static int _add_source(radiomp3_t *s, const char *arg, int stream)
{
	static const char *what[2] = {
		"file (needs a number that isn't a multiple of 10)",
		"stream (needs a multiple of 10, not 0 or 100)",
	};
	rm_source_t *src;
	const char *base;
	char *end;
	long id = -1;
	int i;

	if(s->nsources == RM_MAX_SOURCES)
	{
		fprintf(stderr, "radiomp3: At most %d streams and files\n", RM_MAX_SOURCES);
		return(VID_ERROR);
	}

	src = &s->sources[s->nsources++];
	memset(src, 0, sizeof(rm_source_t));

	/* An optional "ID:" in front of the name */
	if(arg[0] >= '0' && arg[0] <= '9')
	{
		long v = strtol(arg, &end, 10);

		if(*end == ':')
		{
			id = v;
			arg = end + 1;
		}
	}

	src->path = arg;
	src->stream = stream;

	if(id < 0)
	{
		/* Streams get 10, 20, ... (skipping 100) and files
		 * 1, 2, 3, ... (skipping multiples of 10) */
		int n = 0;

		for(i = 0; i < s->nsources - 1; i++)
		{
			if(s->sources[i].stream == stream) n++;
		}

		if(stream)
		{
			id = (n + 1) * 10;
			if(id >= _FILLER_ID) id += 10;
		}
		else
		{
			id = n + 1 + n / 9;
		}
	}

	if(id > 0xFFFF || id == _FILLER_ID ||
	   (stream && (id == 0 || id % 10 != 0)) ||
	   (!stream && id != 0 && id % 10 == 0))
	{
		fprintf(stderr, "radiomp3: %s: ID %ld can't carry a %s\n", arg, id, what[stream]);
		return(VID_ERROR);
	}

	src->id = id;

	if(strcmp(arg, "-") == 0)
	{
		if(!stream)
		{
			fprintf(stderr, "radiomp3: Files can't come from stdin, only streams\n");
			return(VID_ERROR);
		}

		if(s->live >= 0)
		{
			fprintf(stderr, "radiomp3: Only one stream can come from stdin\n");
			return(VID_ERROR);
		}

		src->live = 1;
		s->live = s->nsources - 1;

		src->data = malloc(RM_LIVE_BUFFER);
		if(!src->data)
		{
			return(VID_OUT_OF_MEMORY);
		}

		/* Don't hold up the video while waiting for the stream */
		fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
	}
	else if(_load(src) != VID_OK)
	{
		return(VID_ERROR);
	}

	if(!stream)
	{
		/* File info: the name, as far as it fits */
		base = strrchr(arg, '/');
		base = base ? base + 1 : arg;
		i = strlen(base);
		memcpy(src->info, base, i < _INFO_SIZE ? i : _INFO_SIZE);
	}

	return(VID_OK);
}

int radiomp3_init(radiomp3_t *s, vid_t *vid, int nsources, const char *const *sources, const int *streams, int loop, const char *lines, int shared)
{
	int i, level, r;

	memset(s, 0, sizeof(radiomp3_t));
	s->vid = vid;
	s->loop = loop;
	s->live = -1;

	if((r = _parse_lines(s, lines, shared)) != VID_OK)
	{
		return(r);
	}

	for(i = 0; i < nsources; i++)
	{
		if((r = _add_source(s, sources[i], streams[i])) != VID_OK)
		{
			radiomp3_free(s);
			return(r);
		}
	}

	if(s->nsources == 0)
	{
		fprintf(stderr, "radiomp3: Nothing to send\n");
		return(VID_ERROR);
	}

	_rs_init();

	/* The same signal as hacktv's teletext: 66% of the white level */
	level = round((vid->white_level - vid->black_level) * 0.66);

	s->lut = vbidata_init(
		360, vid->width,
		level,
		VBIDATA_FILTER_RC, (double) vid->width / 444, 0.7,
		vid->pixel_rate * (12e-6 - (64e-6 / 444 * 12))
	);

	if(!s->lut)
	{
		radiomp3_free(s);
		return(VID_OUT_OF_MEMORY);
	}

	return(VID_OK);
}

void radiomp3_free(radiomp3_t *s)
{
	int i;

	if(s == NULL) return;

	for(i = 0; i < s->nsources; i++)
	{
		free(s->sources[i].data);
	}

	free(s->lut);

	memset(s, 0, sizeof(radiomp3_t));
}

int radiomp3_render(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	radiomp3_t *rm = arg;
	vid_line_t *l = lines[0];
	int field, n;

	if(l->line >= 7 && l->line <= 22)
	{
		field = 0;
		n = l->line - 7;
	}
	else if(l->line >= 320 && l->line <= 335)
	{
		field = 1;
		n = l->line - 320;
	}
	else
	{
		return(1);
	}

	if(((rm->mask[field] >> n) & 1) == 0)
	{
		return(1);
	}

	/* Don't render if this VBI line has already been allocated */
	if(l->vbialloc != 0)
	{
		return(1);
	}

	/* The line belongs to r@dio.mp3 even when there is nothing to send,
	 * so that teletext doesn't use it */
	l->vbialloc = 1;

	if(rm->packet == rm->npackets && !_next_superblock(rm))
	{
		return(1);
	}

	vbidata_render(rm->lut, rm->packets[rm->packet++], 0, 360, VBIDATA_LSB_FIRST, l);

	return(1);
}

