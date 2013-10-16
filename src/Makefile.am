AM_CPPFLAGS = -I.. -I$(VARNISHSRC)/include -I$(VARNISHSRC) $(JANSSON_CFLAGS) $(GLIB_CFLAGS)

vmoddir = $(VMODDIR)
vmod_LTLIBRARIES = libvmod_json.la

libvmod_json_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
libvmod_json_la_LIBADD = $(JANSSON_LIBS) $(GLIB_LIBS)

libvmod_json_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_json.c

vcc_if.c vcc_if.h: $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod_json.vcc
	@PYTHON@ $(VARNISHSRC)/lib/libvmod_std/vmod.py $(top_srcdir)/src/vmod_json.vcc

VMOD_TESTS = tests/*.vtc
.PHONY: $(VMOD_TESTS)

tests/*.vtc:
	$(VARNISHSRC)/bin/varnishtest/varnishtest -Dvarnishd=$(VARNISHSRC)/bin/varnishd/varnishd -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_json.vcc \
	$(VMOD_TESTS)

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h
