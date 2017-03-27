#!/usr/bin/make -f 

all:
	@gcc -Wall -o check_conntr_states -lmnl -lnetfilter_conntrack -lnfnetlink check_conntr_states.c 

clean:
	@rm -f check_conntr_states
