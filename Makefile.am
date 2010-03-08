MRIM_SOURCES = \
    proto.h \
    mrimprpl.c

lib_LTLIBRARIES = libmrimprpl.la
libmrimprpl_la_SOURCES = $(MRIM_SOURCES)
libmrimprpl_la_LIBADD = $(GLIB_LIBS) $(PURPLE_LIBS)
libmrimprpl_la_CFLAGS = $(GLIB_CFLAGS) $(PURPLE_CFLAGS)

testinstall: all
	test -d ~/.purple/plugins || mkdir ~/.purple/plugins; \
	cp -v .libs/*.so ~/.purple/plugins
