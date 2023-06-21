LDLIBS=-lpcap

all: deauth-attack

mac.o : mac.h mac.cpp

deauth-attack : main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o
