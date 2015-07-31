
include ../Makedefs

MAT = mod_auth_tkt

all: $(TARGET)

$(TARGET): mod_auth_tkt.c ap_compat.h sha2.c sha2.h
	$(APXS) -c -Wc,"-fno-strict-aliasing -Wall -ansi $(CFLAGS)" $(MAT).c sha2.c


install: $(TARGET)
	$(APXS) -i $(TARGET)

clean:
	-rm -f *.o *.lo *.slo $(MAT).so $(MAT).la
	-rm -rf .libs



