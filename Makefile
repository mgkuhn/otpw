#
# Makefile - One-time password login system
#
# Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
#

VERSION=1.4

CC=gcc
CFLAGS=-O -ggdb -W -Wall -Wno-unused-result -fPIC

%.gz: %
	gzip -9c $< >$@

TARGETS=otpw-gen demologin pam_otpw.so pam_otpw.8.gz otpw-gen.1.gz

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

#PAMLIB=/lib/security
PAMLIB=/lib/x86_64-linux-gnu/security

install: install-pam install-gen

install-pam: pam_otpw.so pam_otpw.8.gz
	rsync -t pam_otpw.so $(PAMLIB)/
	rsync -t pam_otpw.8.gz /usr/share/man/man8/
	perl -i.bak -pe 's/^(\@include common-auth)$$/\# $$1\nauth required pam_otpw.so/' /etc/pam.d/sshd
	perl -i.bak -pe 's/^(ChallengeResponseAuthentication\s+)no$$/$$1yes/' \
	  /etc/ssh/sshd_config
	killall -SIGHUP sshd

install-gen: otpw-gen otpw-gen.1.gz
	rsync -t otpw-gen /usr/bin/
	rsync -t otpw-gen.1.gz /usr/share/man/man1/
	-getent passwd otpw && \
	  chown otpw /usr/bin/otpw-gen && chmod u+s /usr/bin/otpw-gen

install-pseudouser:
	adduser --system --gecos 'Pseudouser for storing one-time password files' --home /var/lib/otpw otpw

uninstall-pseudouser:
	deluser --remove-home otpw

uninstall:
	rm -f $(PAMLIB)/pam_otpw.so /usr/share/man/man8/pam_otpw.8.gz
	rm -f /usr/bin/otpw-gen /usr/share/man/man1/otpw-gen.1.gz

clean:
	rm -f $(TARGETS) *~ *.o core

test-login:
	ssh -o PreferredAuthentications=keyboard-interactive localhost
