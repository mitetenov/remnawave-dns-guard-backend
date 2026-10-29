package guard

import "testing"

func TestNotificationIncidents(t *testing.T) {
	for _, test := range []struct {
		name     string
		states   []string
		expected []string
	}{
		{"freshness return is silent", []string{"healthy", "stale", "healthy", "stale", "healthy"}, nil},
		{"suspect or startup is silent", []string{"unknown", "healthy", "suspect", "healthy", "protected", "healthy"}, nil},
		{"real exclusion and full recovery", []string{"suspect", "excluded", "recovering", "healthy"}, []string{"healthy→excluded", "excluded→healthy"}},
		{"outage survives stale and failed recovery", []string{"excluded", "stale", "recovering", "excluded", "recovering", "stale", "healthy"}, []string{"healthy→excluded", "excluded→healthy"}},
		{"manual disable and enable", []string{"disabled", "unknown", "stale", "healthy"}, []string{"healthy→disabled", "disabled→healthy"}},
		{"no repeated outage messages", []string{"excluded", "disabled", "excluded", "healthy", "excluded", "healthy"}, []string{"healthy→excluded", "excluded→healthy", "healthy→excluded", "excluded→healthy"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := "healthy"
			var events []string
			for _, current := range test.states {
				next := notificationTransition(previous, current)
				if next != previous {
					events = append(events, previous+"→"+next)
				}
				previous = next
			}
			if len(events) != len(test.expected) {
				t.Fatalf("events: %v, want %v", events, test.expected)
			}
			for i := range events {
				if events[i] != test.expected[i] {
					t.Fatalf("events: %v, want %v", events, test.expected)
				}
			}
		})
	}
}
