package webtransport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCloseConnGrace(t *testing.T) {
	for name, tt := range map[string]struct {
		rtt, want time.Duration
	}{
		"no RTT sample yet: the floor": {rtt: 0, want: minCloseConnGrace},
		"loopback: the floor":          {rtt: time.Millisecond, want: minCloseConnGrace},
		"three round trips":            {rtt: 100 * time.Millisecond, want: 300 * time.Millisecond},
		"slow path: the ceiling":       {rtt: 2 * time.Second, want: maxCloseConnGrace},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, closeConnGrace(tt.rtt))
		})
	}
}
