
include ../Makedefs

MODULE=modules/mod_auth_tkt.so

$(TARGET): 
	cd ../src && make

$(MODULE): $(TARGET)
	$(APXS) -S LIBEXECDIR=$(BASEDIR)/t/modules -i ../src/$(TARGET)

test_md5: $(MODULE)
	./TEST -clean
	@echo '***********************'
	@echo
	@echo Testing digest_type MD5
	@echo
	@echo '***********************'
	cp extra.conf.$(VERSION).in conf/extra.conf.in
	./TEST -apxs $(APXS) -conf
	./TEST
#	./TEST 01_basic.t
#	./TEST 01_basic.t
#	./TEST 30_vhost_local_secret.t
#	./TEST 31_vhost_global_secret.t

test_sha256: $(MODULE)
	./TEST -clean
	@echo '**************************'
	@echo
	@echo Testing digest_type SHA256
	@echo
	@echo '**************************'
	cp extra.conf.$(VERSION).in conf/extra.conf.in
	perl -i -pe 's/MD5/SHA256/' conf/extra.conf.in
	./TEST -apxs $(APXS) -conf
	./TEST

test_sha512: $(MODULE)
	./TEST -clean
	@echo '**************************'
	@echo
	@echo Testing digest_type SHA512
	@echo
	@echo '**************************'
	cp extra.conf.$(VERSION).in conf/extra.conf.in
	perl -i -pe 's/MD5/SHA512/' conf/extra.conf.in
	./TEST -apxs $(APXS) -conf
	./TEST

test: $(MODULE) test_md5 test_sha256 test_sha512
	
clean:
	./TEST -clean
	rm -f conf/extra.conf.in

realclean:
	./TEST -clean
	rm -f $(MODULE)

# vim:noet
