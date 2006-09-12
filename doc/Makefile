SECTION=3
POD=mod_auth_tkt.pod
MANPAGE=mod_auth_tkt.$(SECTION)

include ../Makedefs 

all: $(MANPAGE)

$(MANPAGE): $(POD)
	pod2man --section=$(SECTION) --release=$(MAT_VERSION) $(POD) $@

install: $(MANPAGE)
	mkdir -p $(DESTDIR)$(MANPATH)/man$(SECTION)
	cp $(MANPAGE) $(DESTDIR)$(MANPATH)/man$(SECTION)
	chmod 644 $(DESTDIR)$(MANPATH)/man$(SECTION)/$(MANPAGE)

clean:
	-rm -f $(MANPAGE)


# arch-tag: 394fedf6-070d-4904-b9d6-31b37eb3f698
# vim:noet

