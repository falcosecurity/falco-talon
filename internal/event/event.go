package event

import (
	"encoding/json"
	"io"
	"time"
)

type Event struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	Source       string                 `json:"source"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Tags         []interface{}          `json:"tags"`
}

func DecodeEvent(payload io.Reader) (Event, error) {
	var event Event

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&event)
	if err != nil {
		return Event{}, err
	}
	return event, nil
}
