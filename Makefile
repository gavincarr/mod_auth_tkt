TARGETS = all install clean
TESTS = test

$(TARGETS): Makedefs
	cd src && $(MAKE) $@
	cd doc && $(MAKE) $@

Makedefs:
	./configure

realclean:
	cd src && make clean
	cd t && make realclean
	test -f Makedefs && rm -f Makedefs

$(TESTS):
	cd t && $(MAKE) $@

# arch-tag: b72771f5-7db6-407d-b4c2-2cd0a48eb1e1
# vim:noet
