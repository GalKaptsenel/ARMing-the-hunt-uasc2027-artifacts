CC     = gcc
CFLAGS = -O2 -march=armv8.3-a -Wall -Wextra -fno-stack-protector
LDLIBS = -lm -ldl
OBJ    = main.o victim.o attacker.o donor.o scoring.o

rsa_leak: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(OBJ): poc.h
main.o:    victim.h attacker.h donor.h scoring.h
victim.o:  victim.h donor.h scoring.h
attacker.o: attacker.h donor.h
donor.o:   donor.h victim.h
scoring.o: scoring.h donor.h

clean:
	rm -f $(OBJ) rsa_leak

.PHONY: clean
