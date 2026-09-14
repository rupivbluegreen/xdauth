package broker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDetector_TripsThresholdOnce(t *testing.T) {
	var events []SecurityEvent
	d := newDetector(abuseThresholds{WrongCode: 3, Window: time.Minute}, func(e SecurityEvent) {
		events = append(events, e)
	})
	now := time.Now()
	for i := 0; i < 5; i++ {
		d.Observe(EventWrongCode, "1.2.3.4", "sess-1", now)
	}

	var abuse, wrong int
	for _, e := range events {
		switch e.Kind {
		case EventSuspectedAbuse:
			abuse++
		case EventWrongCode:
			wrong++
		}
	}
	assert.Equal(t, 5, wrong, "every observation is reported")
	assert.Equal(t, 1, abuse, "suspected_abuse fires exactly once per window")
}

func TestDetector_WindowResets(t *testing.T) {
	var abuse int
	d := newDetector(abuseThresholds{WrongCode: 2, Window: time.Second}, func(e SecurityEvent) {
		if e.Kind == EventSuspectedAbuse {
			abuse++
		}
	})
	now := time.Now()
	d.Observe(EventWrongCode, "k", "s", now)
	d.Observe(EventWrongCode, "k", "s", now)
	assert.Equal(t, 1, abuse)

	d.Observe(EventWrongCode, "k", "s", now.Add(2*time.Second))
	d.Observe(EventWrongCode, "k", "s", now.Add(2*time.Second))
	assert.Equal(t, 2, abuse, "a new window can trip abuse again")
}

func TestDetector_KeysAreIndependent(t *testing.T) {
	var abuse int
	d := newDetector(abuseThresholds{WrongCode: 2, Window: time.Minute}, func(e SecurityEvent) {
		if e.Kind == EventSuspectedAbuse {
			abuse++
		}
	})
	now := time.Now()
	d.Observe(EventWrongCode, "key-a", "s1", now)
	d.Observe(EventWrongCode, "key-b", "s2", now)
	assert.Equal(t, 0, abuse, "distinct keys must not share a counter")
}
