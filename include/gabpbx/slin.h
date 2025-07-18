/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 2010, Digium, Inc.
 *
 * Russell Bryant <russell@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABpbx project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/* Source: beep.sln16
 * Converted to beep.sln via file convert, then converted to hex:
 * od -An -tx2 beep.sln | awk '{for (i=1; i<NF; i++) printf "0x%s, ", $i} {printf("0x%s,\n", $NF)}'
 * Samples were truncated at 160 and 320 bytes.
 */

#ifndef GABPBX_SLIN_H
#define GABPBX_SLIN_H

static uint16_t ex_slin8[] = {
	0x0002, 0xfffc, 0x0000, 0xfffe, 0x0000, 0xfffa, 0x002a, 0x007a,
	0x003a, 0xffbe, 0xff76, 0xff84, 0x0016, 0x007e, 0x0096, 0x00d2,
	0x00b6, 0x00b0, 0xff9a, 0xfe0a, 0xfdfe, 0xfebe, 0xff5c, 0xffb2,
	0x0184, 0x035a, 0x02f6, 0x01e6, 0x0096, 0x003c, 0xfdf0, 0xfbfe,
	0xfc94, 0xfdb0, 0x001c, 0x01fc, 0x03a6, 0x0450, 0x034c, 0x0132,
	0xfe96, 0xfd5a, 0xfc0e, 0xfb14, 0xfb52, 0xfd12, 0xffda, 0x027a,
	0x049a, 0x05e0, 0x0498, 0x01ee, 0xfe80, 0xfb80, 0xf9ee, 0xf9e4,
	0xfbd2, 0xffb4, 0x03ce, 0x06d6, 0x0854, 0x07f6, 0x0506, 0x0052,
	0xfb6e, 0xf79e, 0xf646, 0xf812, 0xfbea, 0x016a, 0x069e, 0x0a2e,
	0x0b30, 0x0856, 0x0296, 0xfba0, 0xf562, 0xf284, 0xf402, 0xf8da,
};

static uint16_t ex_slin16[] = {
	0x0002, 0x0025, 0x005a, 0x0075, 0x006c, 0x0052, 0x0026, 0xffde,
	0xffa0, 0xff81, 0xff70, 0xff70, 0xff9f, 0xfff5, 0x003b, 0x0070,
	0x008a, 0x0087, 0x00a2, 0x00ce, 0x00d3, 0x00ba, 0x00b4, 0x00c0,
	0x0091, 0x0000, 0xff27, 0xfe52, 0xfde5, 0xfdeb, 0xfe25, 0xfe82,
	0xfef1, 0xff4a, 0xff71, 0xff87, 0xfff5, 0x00ee, 0x022b, 0x0316,
	0x0354, 0x0319, 0x02b8, 0x0230, 0x017d, 0x00d4, 0x0073, 0x0052,
	0xffe8, 0xfec3, 0xfd46, 0xfc41, 0xfc08, 0xfc58, 0xfccf, 0xfd63,
	0xfe43, 0xff74, 0x00ac, 0x01a0, 0x0279, 0x035e, 0x0416, 0x0457,
	0x041c, 0x039b, 0x02e1, 0x01d4, 0x0086, 0xff36, 0xfe37, 0xfd9a,
	0xfd0e, 0xfc5c, 0xfba4, 0xfb1e, 0xfaed, 0xfb14, 0xfb8f, 0xfc6c,
	0xfda7, 0xff18, 0x0090, 0x01e5, 0x0315, 0x0433, 0x0520, 0x05ad,
	0x05af, 0x0520, 0x041b, 0x02ba, 0x011e, 0xff72, 0xfdc9, 0xfc3c,
	0xfaf8, 0xfa1d, 0xf9a9, 0xf99c, 0xfa18, 0xfb2b, 0xfcbf, 0xfeaa,
	0x00b9, 0x02cd, 0x04b7, 0x0646, 0x076d, 0x0825, 0x086f, 0x0841,
	0x0767, 0x05e5, 0x03e4, 0x018c, 0xff10, 0xfc8d, 0xfa2d, 0xf842,
	0xf6f8, 0xf65d, 0xf67c, 0xf74e, 0xf8c1, 0xfac6, 0xfd41, 0xfff4,
	0x02ae, 0x054f, 0x07af, 0x099d, 0x0ad8, 0x0b3a, 0x0aba, 0x094f,
	0x0716, 0x0438, 0x00e1, 0xfd56, 0xf9e8, 0xf6d9, 0xf46d, 0xf2f8,
	0xf2a3, 0xf35b, 0xf4fa, 0xf759, 0xfa5d, 0xfdd6, 0x0174, 0x04f5,
	0x0829, 0x0ae4, 0x0cee, 0x0e09, 0x0e0a, 0x0ce8, 0x0acd, 0x07e9,
};

static inline struct ast_frame *slin8_sample(void)
{
	static struct ast_frame f = {
		.frametype = AST_FRAME_VOICE,
		.datalen = sizeof(ex_slin8),
		.samples = ARRAY_LEN(ex_slin8),
		.mallocd = 0,
		.offset = 0,
		.src = __PRETTY_FUNCTION__,
		.data.ptr = ex_slin8,
	};

	f.subclass.format = ast_format_slin;

	return &f;
}

static inline struct ast_frame *slin16_sample(void)
{
	static struct ast_frame f = {
		.frametype = AST_FRAME_VOICE,
		.datalen = sizeof(ex_slin16),
		.samples = ARRAY_LEN(ex_slin16),
		.mallocd = 0,
		.offset = 0,
		.src = __PRETTY_FUNCTION__,
		.data.ptr = ex_slin16,
	};

	f.subclass.format = ast_format_slin16;

	return &f;
}

#endif /* GABPBX_SLIN_H */
