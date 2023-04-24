package main

import (
	"flag"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/JamesYYang/tc-filter/byteorder"
)

type Flags struct {
	KernelBTF string

	FilterInterface string
	FilterProto     string
	FilterSrcIP     string
	FilterDstIP     string
	FilterSrcPort   uint16
	FilterDstPort   uint16
	FilterPort      uint16

	DropPackage bool
}

type FilterConfig struct {
	// Filter l3
	FilterSrcIP [16]byte
	FilterDstIP [16]byte

	// Filter l4
	FilterProto   uint8
	FilterSrcPort uint16
	FilterDstPort uint16
	FilterPort    uint16

	IsDrop byte
}

func SetFlags() *Flags {
	f := &Flags{}
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")

	flag.StringVar(&f.FilterInterface, "filter-if", "", "filter net interface")
	flag.StringVar(&f.FilterProto, "filter-proto", "", "filter L4 protocol (tcp, udp, icmp)")
	flag.StringVar(&f.FilterSrcIP, "filter-src-ip", "", "filter source IP addr")
	flag.StringVar(&f.FilterDstIP, "filter-dst-ip", "", "filter destination IP addr")
	f.FilterSrcPort = uint16(*flag.Uint("filter-src-port", 0, "filter source port"))
	f.FilterDstPort = uint16(*flag.Uint("filter-dst-port", 0, "filter destination port"))
	f.FilterPort = uint16(*flag.Uint("filter-port", 0, "filter either destination or source port"))

	flag.BoolVar(&f.DropPackage, "drop-skb", false, "drop filtered skb")

	return f
}

func GetConfig(flags *Flags) FilterConfig {
	cfg := FilterConfig{}

	if flags.FilterPort > 0 {
		cfg.FilterPort = byteorder.HostToNetwork16(flags.FilterPort)
	} else {
		if flags.FilterSrcPort > 0 {
			cfg.FilterSrcPort = byteorder.HostToNetwork16(flags.FilterSrcPort)
		}
		if flags.FilterDstPort > 0 {
			cfg.FilterDstPort = byteorder.HostToNetwork16(flags.FilterDstPort)
		}
	}

	switch strings.ToLower(flags.FilterProto) {
	case "tcp":
		cfg.FilterProto = syscall.IPPROTO_TCP
	case "udp":
		cfg.FilterProto = syscall.IPPROTO_UDP
	case "icmp":
		cfg.FilterProto = syscall.IPPROTO_ICMP
	}

	if flags.FilterDstIP != "" {
		ip := net.ParseIP(flags.FilterDstIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-dst-ip")
		}
		copy(cfg.FilterDstIP[:], ip.To4()[:])
	}

	if flags.FilterSrcIP != "" {
		ip := net.ParseIP(flags.FilterSrcIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-src-ip")
		}
		copy(cfg.FilterSrcIP[:], ip.To4()[:])

	}

	if flags.DropPackage {
		cfg.IsDrop = 1
	}

	return cfg
}
