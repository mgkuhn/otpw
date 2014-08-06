#
# Makefile - One-time password login system
#
# Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
#

VERSION=1.4

CC=gcc
CFLAGS=-O -ggdb -W -Wall -Wno-unused-result -fPIC

TARGETS=otpw-gen demologin pam_otpw.so

all: $(TARGETS)

otpw-gen: otpw-gen.o rmd160.o md.o otpw.o
	$(CC) -o $@ $+
demologin: demologin.o otpw.o rmd160.o md.o
	$(CC) -o $@ $+ -lcrypt

otpw-gen.o: otpw-gen.c md.h otpw.h
otpw.o: otpw.c otpw.h md.h
md.o: md.c md.h rmd160.h
rmd160.o: rmd160.c rmd160.h
otpw-l.o: otpw-l.c otpw.c otpw.h md.h
pam_otpw.o: pam_otpw.c otpw.h md.h
pam_otpw.so: pam_otpw.o otpw-l.o rmd160.o md.o
	ld --shared -o $@ $+ -lcrypt -lpam -lpam_misc

distribution:
	git archive --prefix otpw-$(VERSION)/ -o otpw-$(VERSION).tar.gz v$(VERSION)

release:
	git diff --exit-code v$(VERSION) -- otpw.html
	rsync -t otpw-$(VERSION).tar.gz $(HOME)/public_html/download/
	rsync -t otpw.html $(HOME)/public_html/

install-pam: pam_otpw.so
	cp $+ /lib/security/

clean:
	rm -f $(TARGETS) *~ *.o core
