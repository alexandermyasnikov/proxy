
all: proxy

proxy: proxy.c
	gcc proxy.c -o proxy_server -g0 -O3 -Wall -Wextra -pedantic

run:
	./proxy_server

