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

# vim:noet
