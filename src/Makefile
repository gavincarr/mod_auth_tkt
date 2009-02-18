
include ../Makedefs 

MAT = mod_auth_tkt

all: $(TARGET)

$(TARGET): mod_auth_tkt.c ap_compat.h
	$(APXS) -c -Wc,"-Wall -ansi $(CFLAGS)" $(MAT).c


install: $(TARGET)
	$(APXS) -i $(TARGET)

clean:
	-rm -f $(MAT).o $(MAT).so $(MAT).la $(MAT).lo $(MAT).slo
	-rm -rf .libs



