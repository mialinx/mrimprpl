SUBDIRS = src img
ACLOCAL_AMFLAGS = -I m4

ti: all
	test -d ~/.purple/plugins || mkdir ~/.purple/plugins; \
	cp -v src/.libs/*.so ~/.purple/plugins
