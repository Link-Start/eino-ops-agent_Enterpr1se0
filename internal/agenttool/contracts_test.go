package agenttool

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHistoryRunSummaryCompletedAtJSONContract(t *testing.T) {
	timestamp := time.Date(2026, time.September, 19, 12, 34, 56, 0, time.UTC)
	for _, test := range []struct {
		name  string
		value HistoryRunSummary
		want  any
	}{
		{name: "zero", value: HistoryRunSummary{}},
		{name: "populated", value: HistoryRunSummary{CompletedAt: timestamp}, want: timestamp.Format(time.RFC3339Nano)},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if got, exists := fields["completed_at"]; got != test.want || exists != (test.want != nil) {
				t.Fatalf("completed_at = %#v, exists = %t, want %#v in %s", got, exists, test.want, encoded)
			}
		})
	}
}
