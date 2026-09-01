package proto

import "fmt"

const (
	DNSChannelPort  = 53
	STUNChannelPort = 3478
)

type ChannelKind int

const (
	KindDNS ChannelKind = iota
	KindSTUN
	KindHop
)

type Channel struct {
	Name   string
	Port   int
	Kind   ChannelKind
	Domain string // dns channel only
}

func DefaultChannels() []Channel {
	return []Channel{
		{Name: "dns", Port: DNSChannelPort, Kind: KindDNS, Domain: DefaultDNSDomain},
		{Name: "stun", Port: STUNChannelPort, Kind: KindSTUN},
	}
}

func ShiftedChannels(offset int) ([]Channel, error) {
	channels := DefaultChannels()
	for i := range channels {
		channels[i].Port += offset
		if channels[i].Port <= 0 || channels[i].Port > 65535 {
			return nil, fmt.Errorf("hydra: channel %q port out of range: %d", channels[i].Name, channels[i].Port)
		}
	}
	return channels, nil
}
