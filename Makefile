#
# Makefile - One-time password login capability
#
# Markus Kuhn <mkuhn@acm.org>, Computer Laboratory, University of Cambridge
#
# $Id: Makefile,v 1.1 1998-01-21 01:06:33 mgk25 Exp $
#

VERSION=1.0

CC=gcc
CFLAGS=-O
#CFLAGS=-ggdb -DDEBUG -O -W -Wall

TARGETS=newpass demologin

all: $(TARGETS)
 
newpass: newpass.o rmd160.o md.o
	$(CC) -o newpass newpass.o rmd160.o md.o
demologin: demologin.o otpw.o rmd160.o md.o
	$(CC) -o demologin demologin.o otpw.o rmd160.o md.o

newpass.o: newpass.c md.h conf.h
otpw.o: otpw.c otpw.h md.h conf.h
md.o: md.c md.h rmd160.h
rmd160.o: rmd160.c rmd160.h

ship: all clean
	ci -l RCS/*
	cd .. ; tar cvf otpw-$(VERSION).tar --exclude otpw/RCS otpw ; \
	gzip -9 otpw-$(VERSION).tar
	mv ../otpw-$(VERSION).tar.gz ${HOME}/public_html/download/
	cp otpw.html otpw.html~
	mv otpw.html~ ${HOME}/public_html/otpw.html 

clean:
	rm -f $(TARGETS) *~ *.o core
