# Makefile for tinydtls
#
# Copyright (C) 2011 Olaf Bergmann <bergmann@tzi.org>
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# the library's version
VERSION:=0.8.2

# tools

SHELL = /bin/sh
MKDIR = mkdir

abs_builddir = /home/user/contiki/apps/tinydtls/aes
top_builddir = ..
top_srcdir:= ..

SOURCES:= rijndael.c
HEADERS:= rijndael.h
OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
CPPFLAGS= -DDTLSv12 -DWITH_SHA256
CFLAGS=-Wall -std=c99 -pedantic 
LDLIBS=
FILES:=Makefile.in $(SOURCES) $(HEADERS) 
DISTDIR=$(top_builddir)/tinydtls-0.8.2

.PHONY: all dirs clean install dist distclean .gitignore doc

.SUFFIXES:
.SUFFIXES:      .c .o

all:

check:	
	echo DISTDIR: $(DISTDIR)
	echo top_builddir: $(top_builddir)

clean:
	@rm -f $(PROGRAMS) main.o $(LIB) $(OBJECTS)
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean ; \
	done

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ $(DISTDIR).tar.gz

dist:	$(FILES)
	test -d $(DISTDIR)/aes || mkdir $(DISTDIR)/aes
	cp -p $(FILES) $(DISTDIR)/aes

install:	$(HEADERS)
	test -d $(includedir)/aes || mkdir -p $(includedir)/aes
	$(install) $(HEADERS) $(includedir)/aes

.gitignore:
	echo "core\n*~\n*.[oa]\n*.gz\n*.cap\n$(PROGRAM)\n$(DISTDIR)\n.gitignore" >$@
