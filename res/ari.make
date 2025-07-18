#
# GABpbx -- A telephony toolkit for Linux.
#
# Generated Makefile for res_ari dependencies.
#
# Copyright (C) 2013, Digium, Inc.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!!!!                               DO NOT EDIT                        !!!!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# This file is generated by a template. Please see the original template at
# rest-api-templates/ari.make.mustache
#

$(call MOD_ADD_C,res_ari_gabpbx,ari/resource_gabpbx.c)
$(call MOD_ADD_C,res_ari_endpoints,ari/resource_endpoints.c)
$(call MOD_ADD_C,res_ari_channels,ari/resource_channels.c)
$(call MOD_ADD_C,res_ari_bridges,ari/resource_bridges.c)
$(call MOD_ADD_C,res_ari_recordings,ari/resource_recordings.c)
$(call MOD_ADD_C,res_ari_sounds,ari/resource_sounds.c)
$(call MOD_ADD_C,res_ari_playbacks,ari/resource_playbacks.c)
$(call MOD_ADD_C,res_ari_device_states,ari/resource_device_states.c)
$(call MOD_ADD_C,res_ari_mailboxes,ari/resource_mailboxes.c)
$(call MOD_ADD_C,res_ari_events,ari/resource_events.c)
$(call MOD_ADD_C,res_ari_applications,ari/resource_applications.c)
