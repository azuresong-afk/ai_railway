package sysstatus

import "testing"

// Разбор ответа adjtimex (ВРМ.1, Р11): TIME_ERROR или STA_UNSYNC — часы не
// синхронизированы; оценка ошибки отрицательной не бывает.
func TestClassifyClock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    int
		status   int64
		esterror int64
		sync     string
		hasErr   bool
	}{
		{"синхронизированы", 0, 0, 120, SyncSynchronized, true},
		{"TIME_ERROR", timeError, 0, 0, SyncUnsynchronized, true},
		{"STA_UNSYNC", 0, staUnsync, 16000000, SyncUnsynchronized, true},
		{"STA_UNSYNC с другими флагами", 0, staUnsync | 0x1, 5, SyncUnsynchronized, true},
		{"другие флаги без UNSYNC", 0, 0x2001, 5, SyncSynchronized, true},
		{"секунда координации", 1, 0, 0, SyncSynchronized, true},
		{"оценки нет", 0, 0, -1, SyncSynchronized, false},
	} {
		c := classifyClock(tc.state, tc.status, tc.esterror)
		if c.Sync != tc.sync || (c.ErrorMicros != nil) != tc.hasErr || (tc.hasErr && *c.ErrorMicros != tc.esterror) {
			t.Errorf("%s: %+v", tc.name, c)
		}
	}
}

// SystemClock не падает и не возвращает посторонних значений на любой ОС.
func TestSystemClockValues(t *testing.T) {
	switch c := SystemClock(); c.Sync {
	case SyncSynchronized, SyncUnsynchronized, SyncUnknown:
	default:
		t.Fatalf("%+v", c)
	}
}
