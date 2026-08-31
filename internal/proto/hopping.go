package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// 5s hop step: short enough to shake per-port DPI tracking, long enough to
// survive typical RTT without client/server step mismatch.
const HoppingStep = 5 * time.Second

func HoppingStepOf(t time.Time) int64 {
	return t.Unix() / int64(HoppingStep/time.Second)
}

// port = base + SHA256(secret || step)[:4] % range
func HoppingPortForStep(secret string, basePort, portRange int, step int64) int {
	if portRange <= 0 {
		return basePort
	}
	hash := sha256.New()
	hash.Write([]byte(secret))
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(step))
	hash.Write(stamp[:])
	sum := hash.Sum(nil)
	offset := int(binary.BigEndian.Uint32(sum[:4]) % uint32(portRange))
	return basePort + offset
}

func GetHoppingPort(secret string, basePort, portRange int) int {
	return HoppingPortForStep(secret, basePort, portRange, HoppingStepOf(time.Now()))
}

// ±1 step tolerance eats RTT skew across the hop boundary.
func ValidateHoppingPort(secret string, basePort, portRange int, port int, now time.Time) bool {
	if portRange <= 0 {
		return port == basePort
	}
	step := HoppingStepOf(now)
	for _, delta := range []int64{-1, 0, 1} {
		if HoppingPortForStep(secret, basePort, portRange, step+delta) == port {
			return true
		}
	}
	return false
}
