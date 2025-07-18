/*
 * GABpbx -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
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

/*! \file
 *
 * \brief Translate between signed linear and Speex (Open Codec)
 *
 * \note This work was motivated by Jeremy McNamara
 * hacked to be configurable by anthm and bkw 9/28/2004
 *
 * \ingroup codecs
 *
 * The Speex library - http://www.speex.org
 *
 */

/*** MODULEINFO
	<depend>speex</depend>
	<depend>speex_preprocess</depend>
	<use type="external">speexdsp</use>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include <speex/speex.h>

/* We require a post 1.1.8 version of Speex to enable preprocessing
 * and better type handling
 */
#ifdef _SPEEX_TYPES_H
#include <speex/speex_preprocess.h>
#endif

#include "gabpbx/translate.h"
#include "gabpbx/module.h"
#include "gabpbx/config.h"
#include "gabpbx/utils.h"
#include "gabpbx/frame.h"
#include "gabpbx/linkedlists.h"

/* For struct ast_rtp_rtcp_report and struct ast_rtp_rtcp_report_block */
#include "gabpbx/rtp_engine.h"

/* codec variables */
static int quality = 3;
static int complexity = 2;
static int enhancement = 0;
static int vad = 0;
static int vbr = 0;
static float vbr_quality = 4;
static int abr = 0;
static int dtx = 0;	/* set to 1 to enable silence detection */
static int exp_rtcp_fb = 0;	/* set to 1 to use experimental RTCP feedback for changing bitrate */

static int preproc = 0;
static int pp_vad = 0;
static int pp_agc = 0;
static float pp_agc_level = 8000; /* XXX what is this 8000 ? */
static int pp_denoise = 0;
static int pp_dereverb = 0;
static float pp_dereverb_decay = 0.4;
static float pp_dereverb_level = 0.3;

#define TYPE_SILENCE	 0x2
#define TYPE_HIGH	 0x0
#define TYPE_LOW	 0x1
#define TYPE_MASK	 0x3

#define	BUFFER_SAMPLES	8000
#define	SPEEX_SAMPLES	160

/* Sample frame data */
#include "gabpbx/slin.h"
#include "ex_speex.h"

struct speex_coder_pvt {
	void *speex;
	SpeexBits bits;
	int framesize;
	int silent_state;

	int fraction_lost;
	int quality;
	int default_quality;

#ifdef _SPEEX_TYPES_H
	SpeexPreprocessState *pp;
	spx_int16_t buf[BUFFER_SAMPLES];
#else
	int16_t buf[BUFFER_SAMPLES];	/* input, waiting to be compressed */
#endif
};

static int speex_encoder_construct(struct ast_trans_pvt *pvt, const SpeexMode *profile, int sampling_rate)
{
	struct speex_coder_pvt *tmp = pvt->pvt;

	if (!(tmp->speex = speex_encoder_init(profile)))
		return -1;

	speex_bits_init(&tmp->bits);
	speex_bits_reset(&tmp->bits);
	speex_encoder_ctl(tmp->speex, SPEEX_GET_FRAME_SIZE, &tmp->framesize);
	speex_encoder_ctl(tmp->speex, SPEEX_SET_COMPLEXITY, &complexity);
#ifdef _SPEEX_TYPES_H
	if (preproc) {
		tmp->pp = speex_preprocess_state_init(tmp->framesize, sampling_rate);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_VAD, &pp_vad);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_AGC, &pp_agc);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_AGC_LEVEL, &pp_agc_level);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_DENOISE, &pp_denoise);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_DEREVERB, &pp_dereverb);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_DEREVERB_DECAY, &pp_dereverb_decay);
		speex_preprocess_ctl(tmp->pp, SPEEX_PREPROCESS_SET_DEREVERB_LEVEL, &pp_dereverb_level);
	}
#endif
	if (!abr && !vbr) {
		speex_encoder_ctl(tmp->speex, SPEEX_SET_QUALITY, &quality);
		if (vad)
			speex_encoder_ctl(tmp->speex, SPEEX_SET_VAD, &vad);
	}
	if (vbr) {
		speex_encoder_ctl(tmp->speex, SPEEX_SET_VBR, &vbr);
		speex_encoder_ctl(tmp->speex, SPEEX_SET_VBR_QUALITY, &vbr_quality);
	}
	if (abr)
		speex_encoder_ctl(tmp->speex, SPEEX_SET_ABR, &abr);
	if (dtx)
		speex_encoder_ctl(tmp->speex, SPEEX_SET_DTX, &dtx);
	tmp->silent_state = 0;

	tmp->fraction_lost = 0;
	tmp->default_quality = vbr ? vbr_quality : quality;
	tmp->quality = tmp->default_quality;
	ast_debug(3, "Default quality (%s): %d\n", vbr ? "vbr" : "cbr", tmp->default_quality);

	return 0;
}

static int lintospeex_new(struct ast_trans_pvt *pvt)
{
	return speex_encoder_construct(pvt, &speex_nb_mode, 8000);
}

static int lin16tospeexwb_new(struct ast_trans_pvt *pvt)
{
	return speex_encoder_construct(pvt, &speex_wb_mode, 16000);
}

static int lin32tospeexuwb_new(struct ast_trans_pvt *pvt)
{
	return speex_encoder_construct(pvt, &speex_uwb_mode, 32000);
}

static int speex_decoder_construct(struct ast_trans_pvt *pvt, const SpeexMode *profile)
{
	struct speex_coder_pvt *tmp = pvt->pvt;

	if (!(tmp->speex = speex_decoder_init(profile)))
		return -1;

	speex_bits_init(&tmp->bits);
	speex_decoder_ctl(tmp->speex, SPEEX_GET_FRAME_SIZE, &tmp->framesize);
	if (enhancement)
		speex_decoder_ctl(tmp->speex, SPEEX_SET_ENH, &enhancement);

	return 0;
}

static int speextolin_new(struct ast_trans_pvt *pvt)
{
	return speex_decoder_construct(pvt, &speex_nb_mode);
}

static int speexwbtolin16_new(struct ast_trans_pvt *pvt)
{
	return speex_decoder_construct(pvt, &speex_wb_mode);
}

static int speexuwbtolin32_new(struct ast_trans_pvt *pvt)
{
	return speex_decoder_construct(pvt, &speex_uwb_mode);
}

/*! \brief convert and store into outbuf */
static int speextolin_framein(struct ast_trans_pvt *pvt, struct ast_frame *f)
{
	struct speex_coder_pvt *tmp = pvt->pvt;

	/* Assuming there's space left, decode into the current buffer at
	   the tail location.  Read in as many frames as there are */
	int x;
	int res;
	int16_t *dst = pvt->outbuf.i16;
	/* XXX fout is a temporary buffer, may have different types */
#ifdef _SPEEX_TYPES_H
	spx_int16_t fout[1024];
#else
	float fout[1024];
#endif

	if (f->datalen == 0) {  /* Native PLC interpolation */
		if (pvt->samples + tmp->framesize > BUFFER_SAMPLES) {
			ast_log_chan(NULL, LOG_WARNING, "Out of buffer space\n");
			return -1;
		}
#ifdef _SPEEX_TYPES_H
		speex_decode_int(tmp->speex, NULL, dst + pvt->samples);
#else
		speex_decode(tmp->speex, NULL, fout);
		for (x=0;x<tmp->framesize;x++) {
			dst[pvt->samples + x] = (int16_t)fout[x];
		}
#endif
		pvt->samples += tmp->framesize;
		pvt->datalen += 2 * tmp->framesize; /* 2 bytes/sample */
		return 0;
	}

	/* Read in bits */
	speex_bits_read_from(&tmp->bits, f->data.ptr, f->datalen);
	for (;;) {
#ifdef _SPEEX_TYPES_H
		res = speex_decode_int(tmp->speex, &tmp->bits, fout);
#else
		res = speex_decode(tmp->speex, &tmp->bits, fout);
#endif
		if (res < 0)
			break;
		if (pvt->samples + tmp->framesize > BUFFER_SAMPLES) {
			ast_log_chan(NULL, LOG_WARNING, "Out of buffer space\n");
			return -1;
		}
		for (x = 0 ; x < tmp->framesize; x++)
			dst[pvt->samples + x] = (int16_t)fout[x];
		pvt->samples += tmp->framesize;
		pvt->datalen += 2 * tmp->framesize; /* 2 bytes/sample */
	}
	return 0;
}

/*! \brief store input frame in work buffer */
static int lintospeex_framein(struct ast_trans_pvt *pvt, struct ast_frame *f)
{
	struct speex_coder_pvt *tmp = pvt->pvt;

	/* XXX We should look at how old the rest of our stream is, and if it
	   is too old, then we should overwrite it entirely, otherwise we can
	   get artifacts of earlier talk that do not belong */
	memcpy(tmp->buf + pvt->samples, f->data.ptr, f->datalen);
	pvt->samples += f->samples;
	return 0;
}

/*! \brief convert work buffer and produce output frame */
static struct ast_frame *lintospeex_frameout(struct ast_trans_pvt *pvt)
{
	struct speex_coder_pvt *tmp = pvt->pvt;
	struct ast_frame *result = NULL;
	struct ast_frame *last = NULL;
	int samples = 0; /* output samples */

	while (pvt->samples >= tmp->framesize) {
		struct ast_frame *current;
		int is_speech = 1;

		speex_bits_reset(&tmp->bits);

#ifdef _SPEEX_TYPES_H
		/* Preprocess audio */
		if (preproc)
			is_speech = speex_preprocess(tmp->pp, tmp->buf + samples, NULL);
		/* Encode a frame of data */
		if (is_speech) {
			/* If DTX enabled speex_encode returns 0 during silence */
			is_speech = speex_encode_int(tmp->speex, tmp->buf + samples, &tmp->bits) || !dtx;
		} else {
			/* 5 zeros interpreted by Speex as silence (submode 0) */
			speex_bits_pack(&tmp->bits, 0, 5);
		}
#else
		{
			float fbuf[1024];
			int x;
			/* Convert to floating point */
			for (x = 0; x < tmp->framesize; x++)
				fbuf[x] = tmp->buf[samples + x];
			/* Encode a frame of data */
			is_speech = speex_encode(tmp->speex, fbuf, &tmp->bits) || !dtx;
		}
#endif
		samples += tmp->framesize;
		pvt->samples -= tmp->framesize;

		/* Use AST_FRAME_CNG to signify the start of any silence period */
		if (is_speech) {
			int datalen = 0; /* output bytes */

			tmp->silent_state = 0;
			/* Terminate bit stream */
			speex_bits_pack(&tmp->bits, 15, 5);
			datalen = speex_bits_write(&tmp->bits, pvt->outbuf.c, pvt->t->buf_size);
			current = ast_trans_frameout(pvt, datalen, tmp->framesize);
		} else if (tmp->silent_state) {
			current = NULL;
		} else {
			struct ast_frame frm = {
				.frametype = AST_FRAME_CNG,
				.src = pvt->t->name,
			};

			/*
			 * XXX I don't think the AST_FRAME_CNG code has ever
			 * really worked for speex.  There doesn't seem to be
			 * any consumers of the frame type.  Everyone that
			 * references the type seems to pass the frame on.
			 */
			tmp->silent_state = 1;

			/* XXX what now ? format etc... */
			current = ast_frisolate(&frm);
		}

		if (!current) {
			continue;
		} else if (last) {
			AST_LIST_NEXT(last, frame_list) = current;
		} else {
			result = current;
		}
		last = current;
	}

	/* Move the data at the end of the buffer to the front */
	if (samples) {
		memmove(tmp->buf, tmp->buf + samples, pvt->samples * 2);
	}

	return result;
}

/*! \brief handle incoming RTCP feedback and possibly edit encoder settings */
static void lintospeex_feedback(struct ast_trans_pvt *pvt, struct ast_frame *feedback)
{
	struct speex_coder_pvt *tmp = pvt->pvt;

	struct ast_rtp_rtcp_report *rtcp_report;
	struct ast_rtp_rtcp_report_block *report_block;

	int fraction_lost;
	int percent;
	int bitrate;
	int q;

	if(!exp_rtcp_fb)
		return;

	/* We only accept feedback information in the form of SR and RR reports */
	if (feedback->subclass.integer != AST_RTP_RTCP_SR && feedback->subclass.integer != AST_RTP_RTCP_RR) {
		return;
	}

	rtcp_report = (struct ast_rtp_rtcp_report *)feedback->data.ptr;
	if (rtcp_report->reception_report_count == 0)
		return;
	report_block = rtcp_report->report_block[0];
	fraction_lost = report_block->lost_count.fraction;
	if (fraction_lost == tmp->fraction_lost)
		return;
	/* Per RFC3550, fraction lost is defined to be the number of packets lost
	 * divided by the number of packets expected. Since it's a 8-bit value,
	 * and we want a percentage value, we multiply by 100 and divide by 256. */
	percent = (fraction_lost*100)/256;
	bitrate = 0;
	q = -1;
	ast_debug(3, "Fraction lost changed: %d --> %d percent loss\n", fraction_lost, percent);
	/* Handle change */
	speex_encoder_ctl(tmp->speex, SPEEX_GET_BITRATE, &bitrate);
	ast_debug(3, "Current bitrate: %d\n", bitrate);
	ast_debug(3, "Current quality: %d/%d\n", tmp->quality, tmp->default_quality);
	/* FIXME BADLY Very ugly example of how this could be handled: probably sucks */
	if (percent < 10) {
		/* Not that bad, default quality is fine */
		q = tmp->default_quality;
	} else if (percent < 20) {
		/* Quite bad, let's go down a bit */
		q = tmp->default_quality-1;
	} else if (percent < 30) {
		/* Very bad, let's go down even more */
		q = tmp->default_quality-2;
	} else {
		/* Really bad, use the lowest quality possible */
		q = 0;
	}
	if (q < 0)
		q = 0;
	if (q != tmp->quality) {
		ast_debug(3, "  -- Setting to %d\n", q);
		if (vbr) {
			float vbr_q = q;
			speex_encoder_ctl(tmp->speex, SPEEX_SET_VBR_QUALITY, &vbr_q);
		} else {
			speex_encoder_ctl(tmp->speex, SPEEX_SET_QUALITY, &q);
		}
		tmp->quality = q;
	}
	tmp->fraction_lost = fraction_lost;
}

static void speextolin_destroy(struct ast_trans_pvt *arg)
{
	struct speex_coder_pvt *pvt = arg->pvt;

	speex_decoder_destroy(pvt->speex);
	speex_bits_destroy(&pvt->bits);
}

static void lintospeex_destroy(struct ast_trans_pvt *arg)
{
	struct speex_coder_pvt *pvt = arg->pvt;
#ifdef _SPEEX_TYPES_H
	if (preproc)
		speex_preprocess_state_destroy(pvt->pp);
#endif
	speex_encoder_destroy(pvt->speex);
	speex_bits_destroy(&pvt->bits);
}

static struct ast_translator speextolin = {
	.name = "speextolin",
	.src_codec = {
		.name = "speex",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 8000,
	},
	.dst_codec = {
		.name = "slin",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 8000,
	},
	.format = "slin",
	.newpvt = speextolin_new,
	.framein = speextolin_framein,
	.destroy = speextolin_destroy,
	.sample = speex_sample,
	.desc_size = sizeof(struct speex_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2,
	.native_plc = 1,
};

static struct ast_translator lintospeex = {
	.name = "lintospeex",
	.src_codec = {
		.name = "slin",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 8000,
	},
	.dst_codec = {
		.name = "speex",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 8000,
	},
	.format = "speex",
	.newpvt = lintospeex_new,
	.framein = lintospeex_framein,
	.frameout = lintospeex_frameout,
	.feedback = lintospeex_feedback,
	.destroy = lintospeex_destroy,
	.sample = slin8_sample,
	.desc_size = sizeof(struct speex_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2, /* XXX maybe a lot less ? */
};

static struct ast_translator speexwbtolin16 = {
	.name = "speexwbtolin16",
	.src_codec = {
		.name = "speex",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 16000,
	},
	.dst_codec = {
		.name = "slin",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 16000,
	},
	.format = "slin16",
	.newpvt = speexwbtolin16_new,
	.framein = speextolin_framein,
	.destroy = speextolin_destroy,
	.sample = speex16_sample,
	.desc_size = sizeof(struct speex_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2,
	.native_plc = 1,
};

static struct ast_translator lin16tospeexwb = {
	.name = "lin16tospeexwb",
	.src_codec = {
		.name = "slin",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 16000,
	},
	.dst_codec = {
		.name = "speex",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 16000,
	},
	.format = "speex16",
	.newpvt = lin16tospeexwb_new,
	.framein = lintospeex_framein,
	.frameout = lintospeex_frameout,
	.feedback = lintospeex_feedback,
	.destroy = lintospeex_destroy,
	.sample = slin16_sample,
	.desc_size = sizeof(struct speex_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2, /* XXX maybe a lot less ? */
};

static struct ast_translator speexuwbtolin32 = {
	.name = "speexuwbtolin32",
	.src_codec = {
		.name = "speex",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 32000,
	},
	.dst_codec = {
		.name = "slin",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 32000,
	},
	.format = "slin32",
	.newpvt = speexuwbtolin32_new,
	.framein = speextolin_framein,
	.destroy = speextolin_destroy,
	.desc_size = sizeof(struct speex_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2,
	.native_plc = 1,
};

static struct ast_translator lin32tospeexuwb = {
	.name = "lin32tospeexuwb",
	.src_codec = {
		.name = "slin",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 32000,
	},
	.dst_codec = {
		.name = "speex",
		.type = AST_MEDIA_TYPE_AUDIO,
		.sample_rate = 32000,
	},
	.format = "speex32",
	.newpvt = lin32tospeexuwb_new,
	.framein = lintospeex_framein,
	.frameout = lintospeex_frameout,
	.feedback = lintospeex_feedback,
	.destroy = lintospeex_destroy,
	.desc_size = sizeof(struct speex_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2, /* XXX maybe a lot less ? */
};

static int parse_config(int reload)
{
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_config *cfg = ast_config_load("codecs.conf", config_flags);
	struct ast_variable *var;
	int res;
	float res_f;

	if (cfg == CONFIG_STATUS_FILEMISSING || cfg == CONFIG_STATUS_FILEUNCHANGED || cfg == CONFIG_STATUS_FILEINVALID)
		return 0;

	for (var = ast_variable_browse(cfg, "speex"); var; var = var->next) {
		if (!strcasecmp(var->name, "quality")) {
			res = abs(atoi(var->value));
			if (res > -1 && res < 11) {
				ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting Quality to %d\n",res);
				quality = res;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error Quality must be 0-10\n");
		} else if (!strcasecmp(var->name, "complexity")) {
			res = abs(atoi(var->value));
			if (res > -1 && res < 11) {
				ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting Complexity to %d\n",res);
				complexity = res;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error! Complexity must be 0-10\n");
		} else if (!strcasecmp(var->name, "vbr_quality")) {
			if (sscanf(var->value, "%30f", &res_f) == 1 && res_f >= 0 && res_f <= 10) {
				ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting VBR Quality to %f\n",res_f);
				vbr_quality = res_f;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error! VBR Quality must be 0-10\n");
		} else if (!strcasecmp(var->name, "abr_quality")) {
			ast_log_chan(NULL, LOG_ERROR,"Error! ABR Quality setting obsolete, set ABR to desired bitrate\n");
		} else if (!strcasecmp(var->name, "enhancement")) {
			enhancement = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Perceptual Enhancement Mode. [%s]\n",enhancement ? "on" : "off");
		} else if (!strcasecmp(var->name, "vbr")) {
			vbr = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: VBR Mode. [%s]\n",vbr ? "on" : "off");
		} else if (!strcasecmp(var->name, "abr")) {
			res = abs(atoi(var->value));
			if (res >= 0) {
					if (res > 0)
					ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting ABR target bitrate to %d\n",res);
					else
					ast_verb_chan(NULL, 5, "CODEC SPEEX: Disabling ABR\n");
				abr = res;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error! ABR target bitrate must be >= 0\n");
		} else if (!strcasecmp(var->name, "vad")) {
			vad = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: VAD Mode. [%s]\n",vad ? "on" : "off");
		} else if (!strcasecmp(var->name, "dtx")) {
			dtx = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: DTX Mode. [%s]\n",dtx ? "on" : "off");
		} else if (!strcasecmp(var->name, "preprocess")) {
			preproc = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Preprocessing. [%s]\n",preproc ? "on" : "off");
		} else if (!strcasecmp(var->name, "pp_vad")) {
			pp_vad = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Preprocessor VAD. [%s]\n",pp_vad ? "on" : "off");
		} else if (!strcasecmp(var->name, "pp_agc")) {
			pp_agc = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Preprocessor AGC. [%s]\n",pp_agc ? "on" : "off");
		} else if (!strcasecmp(var->name, "pp_agc_level")) {
			if (sscanf(var->value, "%30f", &res_f) == 1 && res_f >= 0) {
				ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting preprocessor AGC Level to %f\n",res_f);
				pp_agc_level = res_f;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error! Preprocessor AGC Level must be >= 0\n");
		} else if (!strcasecmp(var->name, "pp_denoise")) {
			pp_denoise = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Preprocessor Denoise. [%s]\n",pp_denoise ? "on" : "off");
		} else if (!strcasecmp(var->name, "pp_dereverb")) {
			pp_dereverb = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Preprocessor Dereverb. [%s]\n",pp_dereverb ? "on" : "off");
		} else if (!strcasecmp(var->name, "pp_dereverb_decay")) {
			if (sscanf(var->value, "%30f", &res_f) == 1 && res_f >= 0) {
				ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting preprocessor Dereverb Decay to %f\n",res_f);
				pp_dereverb_decay = res_f;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error! Preprocessor Dereverb Decay must be >= 0\n");
		} else if (!strcasecmp(var->name, "pp_dereverb_level")) {
			if (sscanf(var->value, "%30f", &res_f) == 1 && res_f >= 0) {
				ast_verb_chan(NULL, 5, "CODEC SPEEX: Setting preprocessor Dereverb Level to %f\n",res_f);
				pp_dereverb_level = res_f;
			} else
				ast_log_chan(NULL, LOG_ERROR,"Error! Preprocessor Dereverb Level must be >= 0\n");
		} else if (!strcasecmp(var->name, "experimental_rtcp_feedback")) {
			exp_rtcp_fb = ast_true(var->value) ? 1 : 0;
			ast_verb_chan(NULL, 5, "CODEC SPEEX: Experimental RTCP Feedback. [%s]\n",exp_rtcp_fb ? "on" : "off");
		}
	}
	ast_config_destroy(cfg);
	return 0;
}

static int reload(void)
{
	if (parse_config(1))
		return AST_MODULE_LOAD_DECLINE;
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_unregister_translator(&speextolin);
	ast_unregister_translator(&lintospeex);
	ast_unregister_translator(&speexwbtolin16);
	ast_unregister_translator(&lin16tospeexwb);
	ast_unregister_translator(&speexuwbtolin32);
	ast_unregister_translator(&lin32tospeexuwb);

	return 0;
}

static int load_module(void)
{
	int res = 0;

	if (parse_config(0)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	/* XXX It is most likely a bug in this module if we fail to register a translator */
	res |= ast_register_translator(&speextolin);
	res |= ast_register_translator(&lintospeex);
	res |= ast_register_translator(&speexwbtolin16);
	res |= ast_register_translator(&lin16tospeexwb);
	res |= ast_register_translator(&speexuwbtolin32);
	res |= ast_register_translator(&lin32tospeexuwb);
	if (res) {
		unload_module();
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "Speex Coder/Decoder",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
);
