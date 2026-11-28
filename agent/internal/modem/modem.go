// Package modem is an optional, off-by-default connect sound: a procedurally generated
// dial-up handshake (DTMF digits, ringback, ANSam answer tone, V.34-style training noise) played
// once, best-effort, after the agent's first successful ingress session. Nothing is embedded;
// every sample is computed deterministically here.
package modem

import (
	"encoding/binary"
	"math"
)

const (
	// SampleRate is mono 16-bit PCM at 8 kHz.
	SampleRate = 8000
	// DialDigits is the fixed number dialled.
	DialDigits = "5551212"
	fadeMS     = 10
)

// Segment names one section of the sound (sample indices into the PCM data).
type Segment struct {
	Name       string
	Start, End int
}

var dtmfRows = [4]float64{697, 770, 852, 941}
var dtmfCols = [4]float64{1209, 1336, 1477, 1633}

const dtmfKeys = "123A456B789C*0#D"

func dtmf(d byte) (row, col float64) {
	for i := 0; i < 16; i++ {
		if dtmfKeys[i] == d {
			return dtmfRows[i/4], dtmfCols[i%4]
		}
	}
	return 0, 0
}

func ms(n int) int { return n * SampleRate / 1000 }

func fade(x []float64, n int) {
	if n*2 > len(x) {
		n = len(x) / 2
	}
	for i := 0; i < n; i++ {
		g := float64(i) / float64(n)
		x[i] *= g
		x[len(x)-1-i] *= g
	}
}

func sine(f, t float64) float64 { return math.Sin(2 * math.Pi * f * t) }

func dtmfSeg() []float64 {
	var out []float64
	for i := 0; i < len(DialDigits); i++ {
		row, col := dtmf(DialDigits[i])
		tone := make([]float64, ms(100))
		for n := range tone {
			t := float64(n) / SampleRate
			tone[n] = 0.3 * (sine(row, t) + sine(col, t)) / 1.0
		}
		fade(tone, ms(5))
		out = append(out, tone...)
		out = append(out, make([]float64, ms(70))...)
	}
	return out
}

func ringbackSeg() []float64 {
	x := make([]float64, ms(900))
	for n := range x {
		t := float64(n) / SampleRate
		x[n] = 0.25 * (sine(440, t) + sine(480, t))
	}
	return x
}

// ansamSeg is the V.8 ANSam: 2100 Hz, 180 degree phase reversals every 450 ms, 15 Hz AM (20%).
func ansamSeg() []float64 {
	x := make([]float64, ms(1350))
	for n := range x {
		t := float64(n) / SampleRate
		sign := 1.0
		if (n/ms(450))%2 == 1 {
			sign = -1
		}
		x[n] = 0.5 * sign * (1 + 0.2*sine(15, t)) * sine(2100, t)
	}
	return x
}

type biquad struct{ b0, b1, b2, a1, a2, x1, x2, y1, y2 float64 }

func newBiquad(lowpass bool, f0, q float64) *biquad {
	w := 2 * math.Pi * f0 / SampleRate
	cw, alpha := math.Cos(w), math.Sin(w)/(2*q)
	a0 := 1 + alpha
	b := &biquad{a1: -2 * cw / a0, a2: (1 - alpha) / a0}
	if lowpass {
		b.b0, b.b1, b.b2 = (1-cw)/2/a0, (1-cw)/a0, (1-cw)/2/a0
	} else {
		b.b0, b.b1, b.b2 = (1+cw)/2/a0, -(1+cw)/a0, (1+cw)/2/a0
	}
	return b
}

func (b *biquad) step(x float64) float64 {
	y := b.b0*x + b.b1*b.x1 + b.b2*b.x2 - b.a1*b.y1 - b.a2*b.y2
	b.x2, b.x1, b.y2, b.y1 = b.x1, x, b.y1, y
	return y
}

// trainingSeg is band-limited LFSR-scrambled noise (x^23 + x^18 + 1, fixed seed) filtered to
// about 600-3400 Hz with two carrier-ish tones mixed in.
func trainingSeg() []float64 {
	n := ms(1000)
	lfsr := uint32(0x2AAAAA)
	hp := []*biquad{newBiquad(false, 600, 0.707), newBiquad(false, 600, 0.707)}
	lp := []*biquad{newBiquad(true, 3400, 0.707), newBiquad(true, 3400, 0.707)}
	x := make([]float64, n)
	for i := range x {
		bit := (lfsr ^ lfsr>>5) & 1 // taps 23 and 18
		lfsr = lfsr>>1 | bit<<22
		v := 1.0
		if bit == 0 {
			v = -1
		}
		for _, f := range hp {
			v = f.step(v)
		}
		for _, f := range lp {
			v = f.step(v)
		}
		t := float64(i) / SampleRate
		x[i] = 0.25*v + 0.12*sine(1800, t) + 0.08*sine(2400, t)
	}
	return x
}

// Synth returns the complete WAV file and its segment boundaries (in samples). Deterministic.
func Synth() ([]byte, []Segment) {
	parts := []struct {
		name string
		x    []float64
	}{{"dtmf", dtmfSeg()}, {"ringback", ringbackSeg()}, {"ansam", ansamSeg()}, {"training", trainingSeg()}}
	var pcm []int16
	var segs []Segment
	for _, p := range parts {
		fade(p.x, ms(fadeMS))
		s := Segment{Name: p.name, Start: len(pcm)}
		for _, v := range p.x {
			pcm = append(pcm, int16(math.Round(v*32767)))
		}
		s.End = len(pcm)
		segs = append(segs, s)
	}
	w := make([]byte, 44+2*len(pcm))
	le := binary.LittleEndian
	copy(w[0:], "RIFF")
	le.PutUint32(w[4:], uint32(len(w)-8))
	copy(w[8:], "WAVEfmt ")
	le.PutUint32(w[16:], 16)
	le.PutUint16(w[20:], 1)
	le.PutUint16(w[22:], 1)
	le.PutUint32(w[24:], SampleRate)
	le.PutUint32(w[28:], SampleRate*2)
	le.PutUint16(w[32:], 2)
	le.PutUint16(w[34:], 16)
	copy(w[36:], "data")
	le.PutUint32(w[40:], uint32(2*len(pcm)))
	for i, v := range pcm {
		le.PutUint16(w[44+2*i:], uint16(v))
	}
	return w, segs
}
