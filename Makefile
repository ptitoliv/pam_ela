CFLAGS += -Wall -Wextra -O2 -fPIC $(shell pkg-config --cflags libnl-route-3.0)
LDFLAGS += $(shell pkg-config --libs libnl-route-3.0)
PREFIX ?= /lib/security
DESTDIR ?=

MODULE=pam_ela.so

all: $(MODULE)

%.so: %.o
	ld -x --shared -o $@ $< $(LDFLAGS)

clean:
	rm -f $(MODULE) $(MODULE:.so=.o)

install: $(MODULE)
	mkdir -p -- "$(DESTDIR)$(PREFIX)"
	install -- "$<" "$(DESTDIR)$(PREFIX)"

uninstall:
	rm -f -- "$(DESTDIR)$(PREFIX)/$(MODULE)"

.PHONY: all test clean install uninstall
