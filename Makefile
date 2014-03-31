#
# Makefile - One-time password login system
#
# Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
#

VERSION=1.4

CC=gcc
CFLAGS=-O -ggdb -W -Wall
# Note: on Linux x86_64  architectures, it seems that -fPIC is also
# required in CFLAGS for anything that will be linked with --shared

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

snapshot: all clean
	cvs diff
	cd .. ; tar cvzf - --exclude otpw/CVS otpw | \
	ssh trillium "cat >public_html/download/otpw-snapshot.tar.gz"
	scp otpw.html trillium:public_html/otpw-snapshot.html

ship: snapshot
	cvs tag -c rel-`echo $(VERSION) | tr . -`
	cd .. ; tar cvzf - --exclude otpw/CVS otpw | \
	ssh trillium "cat >public_html/download/otpw-$(VERSION).tar.gz"
	scp otpw.html trillium:public_html/
	ssh trillium rm -f public_html/download/otpw-snapshot.tar.gz \
	  public_html/otpw-snapshot.html

install-pam: pam_otpw.so
	cp $+ /lib/security/

clean:
	rm -f $(TARGETS) *~ *.o core
