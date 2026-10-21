package auth

import (
	"strings"
	"testing"
)

func TestQRMatrix(t *testing.T) {
	rows, err := qrMatrix(otpauthURI("ivanov", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	// Размер версии v — 17 + 4v модулей; матрица квадратная, только 0 и 1.
	n := len(rows)
	if n < 21 || (n-17)%4 != 0 {
		t.Fatalf("размер %d", n)
	}
	for i, r := range rows {
		if len(r) != n || strings.Trim(r, "01") != "" {
			t.Fatalf("ряд %d: %q", i, r)
		}
	}
	// Поисковый узор в левом верхнем углу: 7 тёмных модулей в первом ряду.
	if !strings.HasPrefix(rows[0], "1111111") || !strings.HasPrefix(rows[6], "1111111") || rows[3][:7] != "1011101" {
		t.Fatalf("нет поискового узора: %q %q", rows[0], rows[3])
	}
	for _, bad := range []string{"", strings.Repeat("a", maxQRText+1)} {
		if _, err := qrMatrix(bad); err == nil {
			t.Errorf("принят текст длиной %d", len(bad))
		}
	}
}
