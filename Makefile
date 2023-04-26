CLANG ?= clang-12
CFLAGS := '-O2 -g -Wall -Werror $(CFLAGS)'
TARGETS ?= bpf
HEADERS ?= ./ebpf/headers

all: probe build

probe: export GOPACKAGE=main
probe:
	bpf2go -cc $(CLANG) -cflags $(CFLAGS) -target $(TARGETS) -type net_packet_event TCFilter ./ebpf/tc_filter.bpf.c -- -I $(HEADERS) 

build:
	go build -o tc-filter

run:
	./tc-filter --filter-proto=icmp