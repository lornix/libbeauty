include $(top_srcdir)/misc/Makefile.common

#AM_CPPFLAGS = -I$(top_srcdir)/src/input
AM_CFLAGS = -O0 -g3 -Wall
#CFLAGS = -O0 -g3 -Wall

#modulesdir = $(pkglibdir)/instruction_decoder
lib_LTLIBRARIES = libbeauty_ll_inst_to_rtl.la
#bin_PROGRAMS = dis

#noinst_HEADERS = \
#	opcodes.h

libbeauty_ll_inst_to_rtl_la_SOURCES = \
	dis.c

libbeauty_ll_inst_to_rtl_la_LDFLAGS = \
	 -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
