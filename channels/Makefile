#
# GABpbx -- An open source telephony toolkit.
#
# Makefile for channel drivers
#
# Copyright (C) 1999-2006, Digium, Inc.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

-include $(ASTTOPDIR)/menuselect.makeopts $(ASTTOPDIR)/menuselect.makedeps

MODULE_PREFIX=chan
MENUSELECT_CATEGORY=CHANNELS
MENUSELECT_DESCRIPTION=Channel Drivers

all: _all

include $(ASTTOPDIR)/Makefile.moddir_rules

$(call MOD_ADD_C,chan_iax2,$(wildcard iax2/*.c))
iax2/parser.o: _ASTCFLAGS+=$(call get_menuselect_cflags,MALLOC_DEBUG)

$(call MOD_ADD_C,chan_pjsip,$(wildcard pjsip/*.c))
$(call MOD_ADD_C,chan_dahdi,$(wildcard dahdi/*.c) sig_analog.c sig_pri.c sig_ss7.c)

chan_dahdi.o: _ASTCFLAGS+=$(call get_menuselect_cflags,LOTS_OF_SPANS)
chan_unistim.o: _ASTCFLAGS+=$(AST_NO_FORMAT_TRUNCATION)
chan_phone.o: _ASTCFLAGS+=$(AST_NO_FORMAT_TRUNCATION)

$(call MOD_ADD_C,console_video.c vgrabbers.c console_board.c)
