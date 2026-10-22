package guard

type poolTargetSummary struct {
	Active      int    `json:"active"`
	Total       int    `json:"total"`
	Status      string `json:"status"`
	unconfirmed bool
}

func (a *App) poolList() []row {
	summaries := map[string]poolTargetSummary{}
	// Reuse the effective statuses from the detail view, including stale probes.
	for _, target := range a.targetViews(a.s.all("SELECT * FROM targets")) {
		id := str(target["pool_id"])
		summary := summaries[id]
		summary.Total++
		if truth(target["dns_uncertain"]) || target["dns_pending_action"] != nil {
			summary.unconfirmed = true
		}
		if truth(target["dns_present"]) && !truth(target["dns_uncertain"]) && target["dns_pending_action"] == nil {
			summary.Active++
			if summary.Active == 1 {
				summary.Status = "healthy"
			}
			switch str(target["status"]) {
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
	out := []row{}
	for _, pool := range a.s.all("SELECT * FROM pools ORDER BY created_at") {
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
