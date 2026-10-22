package gateway

import (
	"testing"
	"time"
)

// Число провалов в heartbeat ограничено пределом сервера (1000); итог до
// первой проверки — nil; снимок не делится с хранилищем.
func TestReportsSnapshot(t *testing.T) {
	var r Reports
	if st, in, keys, vf := r.snapshot(); st != nil || in != nil || keys != nil || vf != nil {
		t.Fatal("итоги до проверки")
	}
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.FixedZone("x", 3*3600))
	r.SetSelftest(false, at, 1<<20)
	r.SetIntegrity(false, at, "files_mismatch", -5, Manifest{})
	st, in, _, _ := r.snapshot()
	if st.Failed != maxReportFailed || in.Failed != 0 || st.CheckedAt.Location() != time.UTC {
		t.Fatalf("%+v %+v", st, in)
	}
	st.Failed = 7
	if in.ManifestCreated != nil || in.ManifestVersion != "" {
		t.Fatalf("манифест без манифеста: %+v", in)
	}
	if again, _, _, _ := r.snapshot(); again.Failed != maxReportFailed {
		t.Fatal("снимок разделяет память с хранилищем")
	}
	var nilReports *Reports
	if st, in, _, _ := nilReports.snapshot(); st != nil || in != nil {
		t.Fatal("nil Reports")
	}
}
