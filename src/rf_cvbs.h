/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
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

#ifndef _RF_CVBS_H
#define _RF_CVBS_H

/* CVBS file sample encodings */
#define RF_CVBS_U10 0 /* CVBS_U10_4FSC */
#define RF_CVBS_U16 1 /* CVBS_U16_4FSC */

struct vid_t;

extern int rf_cvbs_open(rf_t *s, const char *filename, const struct vid_t *vid, int encoding, const char *notes);

#endif

