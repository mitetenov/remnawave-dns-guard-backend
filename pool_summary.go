package guard

type poolTargetSummary struct {
	Active      int    `json:"active"`
	Total       int    `json:"total"`
	Status      string `json:"status"`
	unconfirmed bool
}

const summaryTargets = "SELECT id,pool_id,manual_enabled,status,dns_present,dns_uncertain,last_checked_at,dns_action FROM targets"

func (a *App) addOverviewCounts(result row) {
	pools := a.s.all("SELECT id,interval_seconds,failure_threshold,recovery_threshold FROM pools")
	targets := a.s.all(summaryTargets)
	view := a.s.probeView(pools, "SELECT "+probeSummaryColumns+" FROM target_checks")
	healthy, excluded, stale := 0, 0, 0
	for _, target := range targets {
		status, _ := view.summary(target).statuses(target)
		uncertain := truth(target["dns_uncertain"])
		if status == "healthy" && !uncertain {
			healthy++
		}
		if truth(target["manual_enabled"]) && !truth(target["dns_present"]) && !uncertain {
			excluded++
		}
		if status == "stale" {
			stale++
		}
	}
	result["pools"], result["targets"], result["healthy"], result["excluded"], result["stale"] = len(pools), len(targets), healthy, excluded, stale
}

func (a *App) poolList() []row {
	pools := a.s.all("SELECT * FROM pools ORDER BY created_at")
	view := a.s.probeView(pools, "SELECT "+probeSummaryColumns+" FROM target_checks")
	summaries := make(map[string]poolTargetSummary, len(pools))
	for _, target := range a.s.all(summaryTargets) {
		id := str(target["pool_id"])
		summary := summaries[id]
		summary.Total++
		unconfirmed := truth(target["dns_uncertain"]) || target["dns_action"] != nil
		if unconfirmed {
			summary.unconfirmed = true
		}
		if truth(target["dns_present"]) && !unconfirmed {
			summary.Active++
			if summary.Active == 1 {
				summary.Status = "healthy"
			}
			status, _ := view.summary(target).statuses(target)
			switch status {
			case "suspect", "protected":
				summary.Status = "suspect"
			case "healthy":
			default:
				if summary.Status != "suspect" {
					summary.Status = "unknown"
				}
			}
		}
		summaries[id] = summary
	}
	out := make([]row, 0, len(pools))
	for _, pool := range pools {
		summary := summaries[str(pool["id"])]
		if summary.Active == 0 {
			summary.Status = "unknown"
			if summary.Total > 0 && !summary.unconfirmed {
				summary.Status = "excluded"
			}
		}
		value := poolView(pool)
		value["target_summary"] = summary
		out = append(out, value)
	}
	return out
}
