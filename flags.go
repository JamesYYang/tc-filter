package main

import "flag"

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
