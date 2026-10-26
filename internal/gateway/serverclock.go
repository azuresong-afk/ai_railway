package gateway

import (
	"sync"
	"time"
)

// ServerClock — часы для сроков исключений политики (3Н40 ревью 3.r3): не
// раньше времени сервера управления из последнего heartbeat плюс время,
// прошедшее с него по монотонным часам. Шлюз с часами, отставшими на
// несколько суток, иначе применял бы исключение, которое консоль уже
// показывает истёкшим. Часы шлюза, ушедшие вперёд, исключение только
// укорачивают: это строже, поэтому берётся большее из двух. Без heartbeat
// (автономная работа) — часы шлюза.
type ServerClock struct {
	// wall — часы шлюза; nil — time.Now (тесты подменяют).
	wall func() time.Time

	mu sync.Mutex
	// server — время сервера из ответа heartbeat, mono — момент получения
	// ответа с монотонным отсчётом.
	server, mono time.Time
}

// Observe запоминает время сервера server из ответа, полученного в at
// (time.Now() с монотонным отсчётом). Нулевое server не меняет оценку.
func (c *ServerClock) Observe(server, at time.Time) {
	if c == nil || server.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.server, c.mono = server, at
}

// Now — большее из часов шлюза и оценки времени сервера.
func (c *ServerClock) Now() time.Time {
	local := time.Now()
	if c == nil {
		return local
	}
	if c.wall != nil {
		local = c.wall()
	}
	c.mu.Lock()
	server, mono := c.server, c.mono
	c.mu.Unlock()
	if server.IsZero() {
		return local
	}
	// time.Since по монотонному отсчёту: перевод часов шлюза оценку не
	// сдвигает.
	if est := server.Add(time.Since(mono)); est.After(local) {
		return est
	}
	return local
}
