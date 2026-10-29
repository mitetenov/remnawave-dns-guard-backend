package guard

import "strings"

// Remember the last terminal notification state through transient probe/control
// states. A return of fresh observations alone is not a server recovery.
func notificationTransition(previous, current string) string {
	if previous == "healthy" && oneOf(current, "excluded", "disabled") {
		return current
	}
	if oneOf(previous, "excluded", "disabled") && current == "healthy" {
		return current
	}
	return previous
}

// Generate both SQL expressions from the same policy exercised by unit tests.
// The inputs are fixed internal status names, never request data.
func notificationPolicySQL() (string, string) {
	var cases, events []string
	states := []string{"healthy", "excluded", "disabled"}
	for _, previous := range states {
		for _, current := range states {
			next := notificationTransition(previous, current)
			if next == previous {
				continue
			}
			condition := "(n.terminal_status='" + previous + "' AND v.status='" + current + "')"
			cases = append(cases, "WHEN "+condition+" THEN '"+next+"'")
			events = append(events, condition)
		}
	}
	return "CASE " + strings.Join(cases, " ") + " ELSE n.terminal_status END", "(" + strings.Join(events, " OR ") + ")"
}

func notificationObserveSQL(where string) string {
	return `INSERT INTO notification_target_status (target_id,status,terminal_status)
 SELECT v.id,v.status,` + notificationNextStateSQL + `
 FROM notification_target_states v JOIN notification_target_status n ON n.target_id=v.id
 WHERE ` + where + `
 ON CONFLICT(target_id) DO UPDATE SET status=excluded.status,terminal_status=excluded.terminal_status
 WHERE notification_target_status.status!=excluded.status OR notification_target_status.terminal_status!=excluded.terminal_status`
}
