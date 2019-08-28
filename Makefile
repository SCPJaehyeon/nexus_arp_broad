all: arp_spoof

arp_spoof: main.o
	gcc -o arp_spoof main.o -lpcap

main.o: header.h main.cpp
	gcc -c -o main.o main.cpp

clean:
	rm -rf main.o arp_spoof
