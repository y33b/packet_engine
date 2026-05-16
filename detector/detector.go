package detector

import (
	//	"fmt"
	"nexus/model"
	"time"
)

type Detector struct{}

func clamp(v float64) float64 {
	if v > 1 {
		return 1
	}
	if v < 0 {
		return 0
	}
	return v
}

func (d *Detector) Analyze(s *model.IPStats) model.Alert {

	score := 0.0
	portCount := len(s.Ports)

	theme := "NORMAL"
	if s.RequestsPerSec > 20 {
		score += 0.1
	}
	if s.RequestsPerSec > 60 {
		score += 0.2
	}
	if s.RequestsPerSec > 120 {
		score += 0.3
	}
	if portCount > 10 && s.RequestsPerSec < 80 {
		score += 0.2
	}
	if portCount > 25 && s.RequestsPerSec < 50 {
		score += 0.4
	}

	if s.FailedAtt > 5 {
		score += 0.3
	}
	if s.FailedAtt > 15 {
		score += 0.4
	}

	score = clamp(score)

	alert := model.Alert{
		IP:        s.IP,
		Timestamp: time.Now().Unix(),
		Risk:      score,
	}
	switch {
	case score >= 0.85:
		alert.Type = model.PORT_SCAN
		alert.Message = "SCAN: high confidence port scanning behavior"
		theme = "PORT_SCAN"

	case score >= 0.8:
		alert.Type = model.FLOOD
		alert.Message = "FLOOD: abnormal traffic burst detected"
		theme = "FLOOD"

	case score >= 0.4:
		alert.Type = model.ANOMALY_DETECTED
		alert.Message = "ANOMALY: unusual behavior pattern"
		theme = "ANOMALY"

	default:
		alert.Type = model.SUSPICIOUS
		alert.Message = "NORMAL: traffic within baseline"
		theme = "NORMAL"
	}

	alert.Message = theme + " | " + alert.Message

	return alert
}
