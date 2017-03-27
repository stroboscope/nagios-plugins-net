#!/usr/bin/make -f 

all:
	cd check-conntr-states && make
	cd check-sockets && make 

clean:
	cd check-conntr-states && make clean
	cd check-sockets && make clean

