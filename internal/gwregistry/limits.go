package gwregistry

import (
	"fmt"
	"time"
)

// Limits — заполнение и вытеснения счётчиков в памяти шлюза с его запуска
// из heartbeat (задача 5.9 этапа 5; 4Н11, 4Н13 ревью 4.r1–4.r2). Поле
// heartbeat необязательное: шлюз прежней версии его не присылает.
type Limits struct {
	// ToolRate — счётчики лимитов вызовов инструментов; nil — нет данных.
	ToolRate *ToolRateLimits
	// Sessions — состояния session.risk; nil — нет данных.
	Sessions *SessionLimits
}

// ToolRateLimits — счётчики лимитов вызовов инструментов шлюза.
type ToolRateLimits struct {
	Keys, MaxKeys int64
	Evictions     int64
}

// SessionLimits — состояния session.risk шлюза: Evictions — из-за общего
// предела, AppEvictions — из-за доли приложения.
type SessionLimits struct {
	Sessions, MaxSessions, MaxAppSessions int64
	Evictions, AppEvictions               int64
}

// LimitsMark — последние счётчики шлюза: время heartbeat и запуск
// процесса шлюза (по нему видно, что счётчики начаты заново).
type LimitsMark struct {
	Limits
	At        time.Time
	StartedAt time.Time
}

// maxLimitCount — предел значений счётчиков (как у счётчиков бюджета).
const maxLimitCount = 1 << 62

func checkCount(name string, v int64) error {
	if v < 0 || v > maxLimitCount {
		return fmt.Errorf("%w: limits.%s — от 0 до 2^62", ErrInvalidRequest, name)
	}
	return nil
}

// validate — счётчики неотрицательны, заполнение не больше предела,
// предел ключей и сессий положителен, доля приложения не больше предела.
func (l *Limits) validate() error {
	if l == nil {
		return nil
	}
	if l.ToolRate == nil && l.Sessions == nil {
		return fmt.Errorf("%w: limits — нужен tool_rate или sessions", ErrInvalidRequest)
	}
	if t := l.ToolRate; t != nil {
		for _, c := range []struct {
			n string
			v int64
		}{{"tool_rate.keys", t.Keys}, {"tool_rate.max_keys", t.MaxKeys}, {"tool_rate.evictions", t.Evictions}} {
			if err := checkCount(c.n, c.v); err != nil {
				return err
			}
		}
		if t.MaxKeys == 0 || t.Keys > t.MaxKeys {
			return fmt.Errorf("%w: limits.tool_rate — keys не больше max_keys, max_keys больше 0", ErrInvalidRequest)
		}
	}
	if s := l.Sessions; s != nil {
		for _, c := range []struct {
			n string
			v int64
		}{{"sessions.sessions", s.Sessions}, {"sessions.max_sessions", s.MaxSessions}, {"sessions.max_app_sessions", s.MaxAppSessions},
			{"sessions.evictions", s.Evictions}, {"sessions.app_evictions", s.AppEvictions}} {
			if err := checkCount(c.n, c.v); err != nil {
				return err
			}
		}
		if s.MaxSessions == 0 || s.MaxAppSessions == 0 || s.Sessions > s.MaxSessions || s.MaxAppSessions > s.MaxSessions {
			return fmt.Errorf("%w: limits.sessions — sessions и max_app_sessions не больше max_sessions, пределы больше 0", ErrInvalidRequest)
		}
	}
	return nil
}

// observeLimits запоминает счётчики шлюза из принятого heartbeat. Хранятся
// в памяти сервера: это счётчики процесса шлюза, они приходят с каждым
// heartbeat (раз в 30 с), после перезапуска сервера — с первым же. Шлюз
// без поля (прежняя версия) или остановленный — данных нет. Записей не
// больше, чем действующих шлюзов, прошедших mTLS.
func (s *Service) observeLimits(gatewayID string, in HeartbeatInput, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Limits == nil || in.Stopping {
		delete(s.limits, gatewayID)
		return
	}
	s.limits[gatewayID] = LimitsMark{Limits: *in.Limits, At: now, StartedAt: in.StartedAt}
}

// GatewayLimits — последние счётчики каждого шлюза по ID (копия).
func (s *Service) GatewayLimits() map[string]LimitsMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]LimitsMark, len(s.limits))
	for id, m := range s.limits {
		out[id] = m
	}
	return out
}
