//go:build !race

package wordpiece

// raceEnabled — тесты собраны с детектором гонок (make test).
const raceEnabled = false
