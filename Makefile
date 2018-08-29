CFLAGS=-Wall -Wextra -O2 -fPIC $(shell pkg-config --cflags libnl-route-3.0)
LDFLAGS=-rdynamic $(shell pkg-config --libs libnl-route-3.0)
PREFIX=/usr/
DESTDIR=

all: pam_ela.so

pam_ela.so: pam_ela.o
	$(CC) -shared -o $@ $^ $(LDFLAGS)

clean:
	rm -f pam_ela.so pam_ela.o

install: pam_ela.so
	mkdir -p -- "$(DESTDIR)$(PREFIX)"/lib64/security/
	install -- "$<" "$(DESTDIR)$(PREFIX)"/lib64/security/

uninstall:
	rm -f -- "$(DESTDIR)$(PREFIX)"/lib64/security/pam_ela.so

.PHONY: all test clean install uninstall
