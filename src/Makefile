
include ../Makedefs 

MAT = mod_auth_tkt

all: $(TARGET)

$(TARGET): mod_auth_tkt.c ap_compat.h sha2.c sha2.h
	$(APXS) -c -Wc,"-fno-strict-aliasing -Wall -ansi $(CFLAGS)" $(MAT).c sha2.c


install: $(TARGET)
	$(APXS) -i $(TARGET)

clean:
	-rm -f $(MAT).o $(MAT).so $(MAT).la $(MAT).lo $(MAT).slo sha2.lo sha2.slo
	-rm -rf .libs



