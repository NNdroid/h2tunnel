package h2tunnel

import "fmt"

const (
	paddingRecordHeaderBytes = resumeHeaderLen
	paddingRecordMaxBytes    = 0xFFFF
)

// paddingPolicy is the validated, hot-path representation of PaddingTuning.
// A zero policy is disabled and performs no random-number generation.
type paddingPolicy struct {
	min int
	max int
}

func compilePaddingPolicy(tuning PaddingTuning) (paddingPolicy, error) {
	minBytes := tuning.MinRecordBytes
	maxBytes := tuning.MaxRecordBytes
	if minBytes == 0 {
		if maxBytes != 0 {
			return paddingPolicy{}, fmt.Errorf("h2tunnel: padding max_record_bytes requires min_record_bytes")
		}
		return paddingPolicy{}, nil
	}
	if minBytes < 0 || maxBytes < 0 {
		return paddingPolicy{}, fmt.Errorf("h2tunnel: padding record sizes must be non-negative")
	}
	if minBytes <= paddingRecordHeaderBytes {
		return paddingPolicy{}, fmt.Errorf("h2tunnel: padding min_record_bytes must be greater than %d", paddingRecordHeaderBytes)
	}
	if minBytes > paddingRecordMaxBytes-8 {
		return paddingPolicy{}, fmt.Errorf("h2tunnel: padding min_record_bytes must not exceed %d", paddingRecordMaxBytes-8)
	}
	if maxBytes == 0 {
		maxBytes = minBytes + minBytes/4
		if maxBytes > paddingRecordMaxBytes {
			maxBytes = paddingRecordMaxBytes
		}
	}
	if maxBytes < minBytes {
		return paddingPolicy{}, fmt.Errorf("h2tunnel: padding max_record_bytes must be greater than or equal to min_record_bytes")
	}
	if maxBytes-minBytes < 8 {
		return paddingPolicy{}, fmt.Errorf("h2tunnel: padding record range must span at least 8 bytes")
	}
	if maxBytes > paddingRecordMaxBytes {
		return paddingPolicy{}, fmt.Errorf("h2tunnel: padding max_record_bytes must not exceed %d", paddingRecordMaxBytes)
	}
	return paddingPolicy{min: minBytes, max: maxBytes}, nil
}

func (p paddingPolicy) enabled() bool { return p.min > 0 }

func (p paddingPolicy) tuning() PaddingTuning {
	if !p.enabled() {
		return PaddingTuning{}
	}
	return PaddingTuning{MinRecordBytes: p.min, MaxRecordBytes: p.max}
}

// targetAtLeast chooses an inclusive random record target in [max(min, base),
// max-reserve]. reserve leaves room for framing whose encoded length depends on
// the amount of padding (MASQUE capsules). If no legal padded target exists,
// base is returned and the caller emits the record without padding.
func (p paddingPolicy) targetAtLeast(base, reserve int) int {
	if !p.enabled() || base >= p.max {
		return base
	}
	lower := p.min
	if base > lower {
		lower = base
	}
	upper := p.max - reserve
	if upper < lower {
		return base
	}
	return lower + fastRand(upper-lower+1)
}

func (p paddingPolicy) paddingFor(base int) int {
	target := p.targetAtLeast(base, 0)
	if target <= base {
		return 0
	}
	return target - base
}

func (p paddingPolicy) dataChunk(remaining, headerBytes int) (chunkLen, padLen int) {
	if !p.enabled() {
		return remaining, 0
	}
	target := p.targetAtLeast(headerBytes, 0)
	capacity := target - headerBytes
	chunkLen = remaining
	if chunkLen > capacity {
		chunkLen = capacity
	}
	return chunkLen, target - headerBytes - chunkLen
}
