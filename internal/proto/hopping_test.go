package proto

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestHoppingPortDeterministicPerStep(t *testing.T) {
	step := int64(123456)
	p1 := HoppingPortForStep("topsecret", 40000, 5000, step)
	p2 := HoppingPortForStep("topsecret", 40000, 5000, step)
	if p1 != p2 {
		t.Fatalf("порт нестабилен внутри шага: %d != %d", p1, p2)
	}
	if p1 < 40000 || p1 >= 45000 {
		t.Fatalf("порт вне диапазона: %d", p1)
	}
	if HoppingPortForStep("topsecret", 40000, 5000, step+1) == p1 && HoppingPortForStep("topsecret", 40000, 5000, step+2) == p1 && HoppingPortForStep("topsecret", 40000, 5000, step+3) == p1 {
		t.Fatal("порт не меняется между шагами (вероятность 1/5000^3)")
	}
}

func TestHoppingSecretChangesPort(t *testing.T) {
	step := int64(777)
	a := HoppingPortForStep("alpha", 40000, 5000, step)
	b := HoppingPortForStep("beta", 40000, 5000, step)
	if a == b {
		t.Fatal("разные секреты дали один порт")
	}
}

func TestValidateHoppingWindow(t *testing.T) {
	now := time.Unix(int64(5)*123456+2, 0)
	port := HoppingPortForStep("topsecret", 40000, 5000, HoppingStepOf(now))
	if !ValidateHoppingPort("topsecret", 40000, 5000, port, now) {
		t.Fatal("текущий шаг должен валидироваться")
	}
	if !ValidateHoppingPort("topsecret", 40000, 5000, port, now.Add(4*time.Second)) {
		t.Fatal("пакет, отправленный в текущем шаге, но принятый в следующем, должен проходить (окно ±1)")
	}
	if !ValidateHoppingPort("topsecret", 40000, 5000, port, now.Add(-4*time.Second)) {
		t.Fatal("пакет из прошлого шага должен проходить (окно ±1)")
	}
	prev := HoppingPortForStep("topsecret", 40000, 5000, HoppingStepOf(now)-2)
	if ValidateHoppingPort("topsecret", 40000, 5000, prev, now) {
		t.Fatal("порт 2 шага назад должен отклоняться")
	}
	if ValidateHoppingPort("wrongsecret", 40000, 5000, port, now) {
		t.Fatal("неверный секрет не должен валидироваться")
	}
}

func TestHoppingStepOf(t *testing.T) {
	if HoppingStepOf(time.Unix(0, 0)) != 0 {
		t.Fatal("шаг нуля")
	}
	if HoppingStepOf(time.Unix(4, 0)) != 0 {
		t.Fatal("4с должно быть шагом 0")
	}
	if HoppingStepOf(time.Unix(5, 0)) != 1 {
		t.Fatal("5с должно быть шагом 1")
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(1))
}
