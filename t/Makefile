
include ../Makedefs

MODULE=modules/mod_auth_tkt.so

$(TARGET): 
	cd ../src && make

$(MODULE): $(TARGET)
	$(APXS) -S LIBEXECDIR=$(BASEDIR)/t/modules -i ../src/$(TARGET)

test: $(MODULE)
	./TEST -clean
	cp extra.conf.$(VERSION).in conf/extra.conf.in
	./TEST -apxs $(APXS) -conf
	./TEST

clean:
	./TEST -clean
	rm -f conf/extra.conf.in

realclean:
	./TEST -clean
	rm -f $(MODULE)

# vim:noet
