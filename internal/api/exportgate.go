package api

import "sync"

// Ограничение одновременных выгрузок событий (В11 ревью 2.r3a). Выгрузка
// держит соединение с СУБД и курсор, пока клиент читает ответ (до
// events.ExportTimeout); без ограничения несколько медленных выгрузок одного
// токена занимали бы все соединения. Сверх предела — 429 без записи в аудит.
const (
	// MaxExportsPerSubject — одновременных выгрузок на пользователя или токен.
	MaxExportsPerSubject = 1
	// MaxExportsTotal — одновременных выгрузок на сервер; меньше размера пула
	// чтения событий, чтобы списки и карточки не ждали выгрузок.
	MaxExportsTotal = 2
	// exportRetryAfter — подсказка клиенту, когда повторить выгрузку, с.
	exportRetryAfter = "30"
)

// ExportGate — счётчики идущих выгрузок: общий и по субъектам.
type ExportGate struct {
	mu         sync.Mutex
	total      int
	bySubject  map[string]int
	maxTotal   int
	maxSubject int
}

// NewExportGate создаёт ограничитель с пределами perSubject и total.
func NewExportGate(perSubject, total int) *ExportGate {
	return &ExportGate{bySubject: map[string]int{}, maxTotal: total, maxSubject: perSubject}
}

// Acquire занимает место выгрузки субъекта subject; false — предел
// исчерпан. Занятое место освобождает Release.
func (g *ExportGate) Acquire(subject string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= g.maxTotal || g.bySubject[subject] >= g.maxSubject {
		return false
	}
	g.total++
	g.bySubject[subject]++
	return true
}

// Release освобождает место, занятое Acquire.
func (g *ExportGate) Release(subject string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.bySubject[subject] <= 1 {
		delete(g.bySubject, subject)
	} else {
		g.bySubject[subject]--
	}
	if g.total > 0 {
		g.total--
	}
}
