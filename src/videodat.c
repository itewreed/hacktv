/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Channel VideoDat output, ported from raspi-teletext                   */
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

/* Channel VideoDat was a data service Pro7 ran in the VBI from 1990 to
 * 1994, in PAL lines 11-13 of the first field and 324-326 of the second.
 * Each line carries 10 bytes as NRZ at 2 Mbit/s, starting about 11.7 µs
 * after 0H. Every byte is sent like an inverted UART frame: a white start
 * bit, the 8 data bits LSB first with 1 = black, and a black stop bit.
 * The packets are built by vdpacket.c.
 *
 * The byte stream comes from one of:
 *
 *   demo          a small text file and the clock, sent over and over
 *   raw:<path>    a byte stream as written by raspi-teletext's vdenc or
 *                 videodat_decoder.py --save-bytes, "raw:-" for stdin
 *   <path>        a file, or a directory of files, sent over and over
 *
 * The decoder is https://github.com/itewreed/channel-videodat-decoder
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include "video.h"
#include "vbidata.h"
#include "vdpacket.h"
#include "videodat.h"

/* Start of the first bit after 0H */
#define VD_START (11.7e-6)

/* Rise and fall time of the bit edges */
#define VD_RISE (120e-9)

/* Clock packets on stream 01 are sent this often (seconds) */
#define VD_CLOCK_INTERVAL (5)

static void _emit(const uint8_t *data, size_t len, void *ctx)
{
	videodat_t *s = ctx;
	
	if(s->buf_len + len > s->buf_size)
	{
		size_t size = s->buf_size ? s->buf_size : 4096;
		uint8_t *buf;
		
		/* Drop the bytes already sent before growing the buffer */
		if(s->buf_pos > 0)
		{
			memmove(s->buf, s->buf + s->buf_pos, s->buf_len - s->buf_pos);
			s->buf_len -= s->buf_pos;
			s->buf_pos = 0;
		}
		
		while(s->buf_len + len > size)
		{
			size *= 2;
		}
		
		if(size > s->buf_size)
		{
			buf = realloc(s->buf, size);
			if(!buf)
			{
				fprintf(stderr, "videodat: Out of memory\n");
				return;
			}
			
			s->buf = buf;
			s->buf_size = size;
		}
	}
	
	memcpy(s->buf + s->buf_len, data, len);
	s->buf_len += len;
	s->bytes_out += len;
}

/* Times follow the position in the byte stream, so that a decoded
 * recording shows the clock running at the right speed, also when
 * hacktv runs faster or slower than real time (eg writing to a file). */
static time_t _stream_time(videodat_t *s)
{
	return(s->t0 + (time_t) (s->bytes_out / s->rate));
}

static time_t _stream_now(void *ctx)
{
	return(_stream_time(ctx));
}

static void _clock_hook(void *ctx)
{
	videodat_t *s = ctx;
	double t = s->bytes_out / s->rate;
	
	if(t >= s->next_clock)
	{
		vd_send_clock(&s->clock, _stream_time(s));
		s->next_clock += VD_CLOCK_INTERVAL;
		
		if(s->next_clock < t)
		{
			s->next_clock = t + VD_CLOCK_INTERVAL;
		}
	}
}

static int _load_file(vd_file_t *f, const char *path)
{
	struct stat st;
	FILE *fp;
	const char *base;
	char *p;
	
	fp = fopen(path, "rb");
	if(!fp || fstat(fileno(fp), &st) != 0)
	{
		fprintf(stderr, "videodat: %s: %s\n", path, strerror(errno));
		if(fp) fclose(fp);
		return(-1);
	}
	
	if(st.st_size > UINT32_MAX)
	{
		fprintf(stderr, "videodat: %s: File too large\n", path);
		fclose(fp);
		return(-1);
	}
	
	base = strrchr(path, '/');
	base = base ? base + 1 : path;
	
	/* VideoDat sends DOS file names, 12 characters at most */
	if(strlen(base) > 12)
	{
		fprintf(stderr, "videodat: %s: Name cut to 12 characters\n", path);
	}
	
	snprintf(f->name, sizeof(f->name), "%s", base);
	for(p = f->name; *p; p++)
	{
		*p = toupper((unsigned char) *p);
	}
	
	f->size = st.st_size;
	f->mtime = st.st_mtime;
	f->data = malloc(f->size ? f->size : 1);
	
	if(!f->data || fread(f->data, 1, f->size, fp) != f->size)
	{
		fprintf(stderr, "videodat: %s: Read failed\n", path);
		free(f->data);
		f->data = NULL;
		fclose(fp);
		return(-1);
	}
	
	fclose(fp);
	
	return(0);
}

static int _add_file(videodat_t *s, const char *path)
{
	vd_file_t *f;
	
	f = realloc(s->files, sizeof(vd_file_t) * (s->nfiles + 1));
	if(!f)
	{
		return(VID_OUT_OF_MEMORY);
	}
	
	s->files = f;
	memset(&s->files[s->nfiles], 0, sizeof(vd_file_t));
	
	if(_load_file(&s->files[s->nfiles], path) != 0)
	{
		return(VID_ERROR);
	}
	
	s->nfiles++;
	
	return(VID_OK);
}

static int _namecmp(const void *a, const void *b)
{
	return(strcmp(*(char * const *) a, *(char * const *) b));
}

static int _load_dir(videodat_t *s, const char *path)
{
	DIR *dir;
	struct dirent *ent;
	struct stat st;
	char filename[PATH_MAX];
	char **names = NULL;
	int i, n = 0;
	int r = VID_OK;
	
	dir = opendir(path);
	if(!dir)
	{
		fprintf(stderr, "videodat: %s: %s\n", path, strerror(errno));
		return(VID_ERROR);
	}
	
	while((ent = readdir(dir)))
	{
		char **p;
		
		/* Skip hidden dot files */
		if(ent->d_name[0] == '.')
		{
			continue;
		}
		
		snprintf(filename, PATH_MAX, "%s/%s", path, ent->d_name);
		if(stat(filename, &st) != 0 || !S_ISREG(st.st_mode))
		{
			continue;
		}
		
		p = realloc(names, sizeof(char *) * (n + 1));
		if(!p)
		{
			r = VID_OUT_OF_MEMORY;
			break;
		}
		
		names = p;
		names[n] = strdup(filename);
		if(!names[n])
		{
			r = VID_OUT_OF_MEMORY;
			break;
		}
		
		n++;
	}
	
	closedir(dir);
	
	/* Send the files in name order */
	if(n > 0)
	{
		qsort(names, n, sizeof(char *), _namecmp);
	}
	
	for(i = 0; i < n; i++)
	{
		if(r == VID_OK)
		{
			r = _add_file(s, names[i]);
		}
		
		free(names[i]);
	}
	
	free(names);
	
	return(r);
}

static int _parse_lines(videodat_t *s, const char *lines)
{
	char *end;
	unsigned long m;
	
	s->mask[0] = s->mask[1] = VD_DEFAULT_MASK;
	
	if(lines == NULL)
	{
		return(VID_OK);
	}
	
	/* <mask>[,<mask>], the first for field 1, the second for field 2 */
	m = strtoul(lines, &end, 0);
	if(end == lines || m > 0xFFFF || (*end != '\0' && *end != ','))
	{
		fprintf(stderr, "videodat: Invalid line mask '%s'\n", lines);
		return(VID_ERROR);
	}
	
	s->mask[0] = s->mask[1] = m;
	
	if(*end == ',')
	{
		lines = end + 1;
		m = strtoul(lines, &end, 0);
		if(end == lines || m > 0xFFFF || *end != '\0')
		{
			fprintf(stderr, "videodat: Invalid line mask '%s'\n", lines);
			return(VID_ERROR);
		}
		
		s->mask[1] = m;
	}
	
	if(s->mask[0] == 0 && s->mask[1] == 0)
	{
		fprintf(stderr, "videodat: The line masks select no lines\n");
		return(VID_ERROR);
	}
	
	return(VID_OK);
}

static int _popcount16(uint16_t v)
{
	int n;
	
	for(n = 0; v; v >>= 1)
	{
		n += v & 1;
	}
	
	return(n);
}

int videodat_init(videodat_t *s, vid_t *vid, const char *source, const char *lines, const char *info)
{
	struct stat fs;
	int level;
	int r;
	
	memset(s, 0, sizeof(videodat_t));
	s->vid = vid;
	
	if(vid->conf.type != VID_RASTER_625)
	{
		fprintf(stderr, "videodat: Only 625 line modes are supported\n");
		return(VID_ERROR);
	}
	
	if((r = _parse_lines(s, lines)) != VID_OK)
	{
		return(r);
	}
	
	/* The high level for the data, 100% of the white level as sent by
	 * raspi-teletext. */
	level = round(vid->white_level - vid->black_level);
	
	/* 100 bits per line at 2 Mbit/s, drawn as rectangular pulses with
	 * raised cosine edges. A raised cosine (sinc) pulse shape would ring
	 * into the sync pulse before the data. */
	s->lut = vbidata_init_step(
		VD_LINE_BITS, vid->width,
		level,
		vid->pixel_rate / VD_BIT_RATE,
		vid->pixel_rate * VD_RISE,
		vid->pixel_rate * VD_START
	);
	
	if(!s->lut)
	{
		return(VID_OUT_OF_MEMORY);
	}
	
	/* Raw byte stream */
	if(strncmp(source, "raw:", 4) == 0)
	{
		if(strcmp(source + 4, "-") == 0)
		{
			s->raw = stdin;
		}
		else
		{
			s->raw = fopen(source + 4, "rb");
			if(!s->raw)
			{
				fprintf(stderr, "videodat: %s: %s\n", source + 4, strerror(errno));
				videodat_free(s);
				return(VID_ERROR);
			}
		}
		
		return(VID_OK);
	}
	
	/* Generated byte stream, the files or the demo. The clock and the
	 * send times follow the bytes sent: 10 bytes per line on every line
	 * of the masks, 25 frames per second. */
	s->rate = (double) VD_LINE_BYTES * (_popcount16(s->mask[0]) + _popcount16(s->mask[1]))
	        * vid->conf.frame_rate.num / vid->conf.frame_rate.den;
	s->t0 = time(NULL);
	s->info = info;
	
	vd_tx_init(&s->tx, _emit, s, 1, 2);
	s->tx.hook = _clock_hook;
	s->tx.now = _stream_now;
	vd_stream_init(&s->stream, &s->tx, 0x03, 0);
	vd_clock_init(&s->clock, &s->tx);
	
	if(strcmp(source, "demo") == 0)
	{
		vd_file_t *f;
		size_t len = 0;
		int n;
		
		s->files = f = calloc(1, sizeof(vd_file_t));
		if(!f || !(f->data = malloc(4096)))
		{
			videodat_free(s);
			return(VID_OUT_OF_MEMORY);
		}
		
		s->nfiles = 1;
		strcpy(f->name, "HACKTV.TXT");
		f->mtime = s->t0;
		
		for(n = 1; len < 4096 - 80; n++)
		{
			len += snprintf((char *) f->data + len, 4096 - len,
				"hacktv VideoDat test, line %d\r\n", n);
		}
		
		f->size = len;
		
		if(s->info == NULL)
		{
			s->info = "HACKTV-VD";
		}
		
		return(VID_OK);
	}
	
	if(stat(source, &fs) != 0)
	{
		fprintf(stderr, "videodat: %s: %s\n", source, strerror(errno));
		videodat_free(s);
		return(VID_ERROR);
	}
	
	r = S_ISDIR(fs.st_mode) ? _load_dir(s, source) : _add_file(s, source);
	
	if(r == VID_OK && s->nfiles == 0)
	{
		fprintf(stderr, "videodat: %s: No files to send\n", source);
		r = VID_ERROR;
	}
	
	if(r != VID_OK)
	{
		videodat_free(s);
		return(r);
	}
	
	return(VID_OK);
}

void videodat_free(videodat_t *s)
{
	int i;
	
	if(s == NULL) return;
	
	if(s->raw && s->raw != stdin)
	{
		fclose(s->raw);
	}
	
	for(i = 0; i < s->nfiles; i++)
	{
		free(s->files[i].data);
	}
	
	free(s->files);
	free(s->buf);
	free(s->lut);
	
	memset(s, 0, sizeof(videodat_t));
}

/* Send the info block (before the first file) or the next file */
static void _next_file(videodat_t *s)
{
	vd_file_t *f;
	
	if(s->next_file == 0 && s->info)
	{
		vd_send_info(&s->stream, s->info, s->nfiles);
	}
	
	f = &s->files[s->next_file];
	vd_send_file(&s->stream, f->name, f->data, f->size, f->mtime);
	
	s->next_file = (s->next_file + 1) % s->nfiles;
}

/* Fetch the bytes of the next line. Returns 0 if there are none. */
static int _next_line(videodat_t *s, uint8_t *bytes)
{
	size_t r;
	
	if(s->raw)
	{
		if(s->raw_eof)
		{
			return(0);
		}
		
		r = fread(bytes, 1, VD_LINE_BYTES, s->raw);
		
		if(r < VD_LINE_BYTES && s->raw != stdin)
		{
			/* Return to the start of the file when we hit the end */
			fseek(s->raw, 0, SEEK_SET);
			
			if(r == 0)
			{
				r = fread(bytes, 1, VD_LINE_BYTES, s->raw);
			}
		}
		else if(r < VD_LINE_BYTES)
		{
			s->raw_eof = 1;
		}
		
		if(r == 0)
		{
			s->raw_eof = 1;
			return(0);
		}
		
		/* Pad a short line with FF, which can't start a sync word */
		memset(bytes + r, 0xFF, VD_LINE_BYTES - r);
		
		return(1);
	}
	
	while(s->buf_len - s->buf_pos < VD_LINE_BYTES)
	{
		size_t len = s->buf_len;
		
		_next_file(s);
		
		if(s->buf_len == len && s->buf_len - s->buf_pos < VD_LINE_BYTES)
		{
			/* Nothing was sent (the packets are still queued in a
			 * group), or out of memory. Try once more before giving up. */
			_next_file(s);
			
			if(s->buf_len == len)
			{
				return(0);
			}
		}
	}
	
	memcpy(bytes, s->buf + s->buf_pos, VD_LINE_BYTES);
	s->buf_pos += VD_LINE_BYTES;
	
	return(1);
}

int videodat_render(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	videodat_t *v = arg;
	vid_line_t *l = lines[0];
	uint8_t bytes[VD_LINE_BYTES];
	uint8_t bits[(VD_LINE_BITS + 7) / 8];
	int field, n, i, x;
	
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
	
	if(((v->mask[field] >> n) & 1) == 0)
	{
		return(1);
	}
	
	/* Don't render if this VBI line has already been allocated */
	if(l->vbialloc != 0)
	{
		return(1);
	}
	
	/* The line belongs to VideoDat even if there is no data for it,
	 * so teletext doesn't use it */
	l->vbialloc = 1;
	
	if(!_next_line(v, bytes))
	{
		return(1);
	}
	
	/* Build the line: per byte a start bit (white), the 8 data bits
	 * LSB first and inverted, and a stop bit (black). Bit 1 = white. */
	memset(bits, 0, sizeof(bits));
	
	for(x = i = 0; i < VD_LINE_BYTES; i++)
	{
		int b, d = bytes[i];
		
		bits[x >> 3] |= 1 << (x & 7);
		x++;
		
		for(b = 0; b < 8; b++, x++, d >>= 1)
		{
			if((d & 1) == 0)
			{
				bits[x >> 3] |= 1 << (x & 7);
			}
		}
		
		x++;
	}
	
	vbidata_render(v->lut, bits, 0, VD_LINE_BITS, VBIDATA_LSB_FIRST, l);
	
	return(1);
}

