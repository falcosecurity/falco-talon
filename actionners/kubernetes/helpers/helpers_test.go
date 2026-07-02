package helpers

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
)

func replicaSet(desired *int32, ready int32) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		Spec:   appsv1.ReplicaSetSpec{Replicas: desired},
		Status: appsv1.ReplicaSetStatus{ReadyReplicas: ready},
	}
}

func int32Ptr(v int32) *int32 { return &v }

func TestHasEnoughHealthyReplicas(t *testing.T) {
	tests := []struct {
		name     string
		rs       *appsv1.ReplicaSet
		minValue int64
		kind     string
		want     bool
		wantErr  bool
	}{
		{name: "absolut met", rs: replicaSet(int32Ptr(10), 5), minValue: 3, kind: "absolut", want: true},
		{name: "absolut exactly met", rs: replicaSet(int32Ptr(10), 3), minValue: 3, kind: "absolut", want: true},
		{name: "absolut not met", rs: replicaSet(int32Ptr(10), 2), minValue: 3, kind: "absolut", want: false},

		// 33% of 10 desired = 3.3 -> ceil = 4
		{name: "percent ceil met", rs: replicaSet(int32Ptr(10), 4), minValue: 33, kind: "percent", want: true},
		{name: "percent ceil not met", rs: replicaSet(int32Ptr(10), 3), minValue: 33, kind: "percent", want: false},
		// 50% of 3 desired = 1.5 -> ceil = 2
		{name: "percent odd desired met", rs: replicaSet(int32Ptr(3), 2), minValue: 50, kind: "percent", want: true},
		{name: "percent odd desired not met", rs: replicaSet(int32Ptr(3), 1), minValue: 50, kind: "percent", want: false},
		// percentage is computed against desired, not ready: 100% of 10 with only 9 ready -> not enough
		{name: "percent against desired", rs: replicaSet(int32Ptr(10), 9), minValue: 100, kind: "percent", want: false},
		// no desired replicas known -> threshold 0 -> always enough
		{name: "percent nil desired", rs: replicaSet(nil, 0), minValue: 50, kind: "percent", want: true},

		{name: "nil replicaset", rs: nil, minValue: 1, kind: "absolut", wantErr: true},
		{name: "unknown kind", rs: replicaSet(int32Ptr(1), 1), minValue: 1, kind: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HasEnoughHealthyReplicas(tt.rs, tt.minValue, tt.kind)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HasEnoughHealthyReplicas() = %v, want %v", got, tt.want)
			}
		})
	}
}
