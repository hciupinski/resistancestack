package doctor

import "time"

const (
	ModeLocal  = "local"
	ModeRemote = "remote"
	ModeAll    = "all"

	StatusPass = "pass"
	StatusWarn = "warn"
	StatusFail = "fail"
)

type Options struct {
	Mode    string
	Version string
}

type Check struct {
	Area           string `json:"area"`
	ID             string `json:"id"`
	Status         string `json:"status"`
	Description    string `json:"description"`
	DetectedValue  string `json:"detected_value"`
	Recommendation string `json:"recommendation,omitempty"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Mode        string    `json:"mode"`
	Status      string    `json:"status"`
	Checks      []Check   `json:"checks"`
}

func (r Report) HasFailures() bool {
	for _, check := range r.Checks {
		if check.Status == StatusFail {
			return true
		}
	}
	return false
}
