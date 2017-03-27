#!/usr/bin/make -f 

all:
	@gcc -Wall -o check_udp_states check_udp_states.c
	@gcc -Wall -o check_udp6_states check_udp6_states.c
	@gcc -Wall -o check_tcp_states check_tcp_states.c
	@gcc -Wall -o check_tcp6_states check_tcp6_states.c

clean:
	@rm -f check_tcp_states check_tcp6_states check_udp_states check_udp6_states
