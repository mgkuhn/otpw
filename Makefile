#
# Makefile - One-time password login capability
#
# Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
#
# $Id: Makefile,v 1.3 2003-06-19 19:49:19 mgk25 Exp $
#

VERSION=1.1

CC=gcc
CFLAGS=-O -W
#CFLAGS=-ggdb -DDEBUG -O -W -Wall

TARGETS=otpw-gen demologin pam_otpw.so

all: $(TARGETS)

otpw-gen: otpw-gen.o rmd160.o md.o
	$(CC) -o $@ $+
demologin: demologin.o otpw.o rmd160.o md.o
	$(CC) -o $@ $+ -lcrypt

otpw-gen.o: otpw-gen.c md.h conf.h
otpw.o: otpw.c otpw.h md.h conf.h
md.o: md.c md.h rmd160.h
rmd160.o: rmd160.c rmd160.h
otpw-l.o: otpw-l.c otpw.c otpw.h md.h conf.h
pam_otpw.o: pam_otpw.c otpw.h md.h conf.h
pam_otpw.so: pam_otpw.o otpw-l.o rmd160.o md.o
	ld --shared -o $@ $+ -lcrypt -lpam -lpam_misc

ship: all clean
	ci -l RCS/*
	cd .. ; tar cvf otpw-$(VERSION).tar --exclude otpw/RCS otpw ; \
	gzip -9 otpw-$(VERSION).tar
	mv ../otpw-$(VERSION).tar.gz ${HOME}/public_html/download/
	cp otpw.html otpw.html~
	mv otpw.html~ ${HOME}/public_html/otpw.html 

clean:
	rm -f $(TARGETS) *~ *.o core
