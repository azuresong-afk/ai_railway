//go:build race

package wordpiece

// raceEnabled — тесты собраны с детектором гонок (make test): замеры
// времени в нём в разы медленнее.
const raceEnabled = true
