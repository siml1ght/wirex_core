package proto

import "fmt"

const (
	DNSChannelPort  = 53
	STUNChannelPort = 3478
)

// the mask prefixes are what DPI sees: "DNS " query bytes on 53, STUN Binding on 3478
type Channel struct {
	Name   string
	Port   int
	Prefix []byte
}

func DefaultChannels() []Channel {
	return []Channel{
		{Name: "dns", Port: DNSChannelPort, Prefix: []byte{0x44, 0x4E, 0x53}},
		{Name: "stun", Port: STUNChannelPort, Prefix: []byte{0x00, 0x01}},
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
