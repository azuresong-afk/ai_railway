package shadowai

import (
	"net/netip"
	"sort"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Новый сервис (DM-37, задача 4.23): сервис каталога, которого не было в
// сводках за 30 суток до первого часа, в котором он встретился в новой
// партии сводок (импорт файла или запись приёма по syslog), и после него.
// Проверка идёт в транзакции записи партии под блокировкой: две партии
// одновременно не поднимут два оповещения об одном сервисе. На каждый новый
// сервис пишется запись аудита shadow_ai.new_service, по ней оповещения
// поднимают встроенное правило shadow_ai.new_service (internal/alerting).
// В записи — сервис, число пользователей и обращений, без псевдонимов.

// NewServiceWindow — сколько суток без сводок делает сервис новым.
const NewServiceWindow = 30 * 24 * time.Hour

// Источники партии сводок.
const (
	SourceImport = "import"
	SourceSyslog = "syslog"
)

// serviceFirst — первый час каждого сервиса партии.
func serviceFirst(aggs []Aggregate) map[string]time.Time {
	out := map[string]time.Time{}
	for _, a := range aggs {
		if t, ok := out[a.Service]; !ok || a.Bucket.Before(t) {
			out[a.Service] = a.Bucket
		}
	}
	return out
}

// firstArrays — сервисы и их первые часы в порядке ID (параметры запроса).
func firstArrays(aggs []Aggregate) ([]string, []time.Time) {
	first := serviceFirst(aggs)
	ids := make([]string, 0, len(first))
	for id := range first {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	at := make([]time.Time, len(ids))
	for i, id := range ids {
		at[i] = first[id]
	}
	return ids, at
}

// newServiceEntries — записи аудита о новых сервисах fresh из партии aggs.
func newServiceEntries(actor audit.Actor, ip netip.Addr, source string, aggs []Aggregate, names map[string]string,
	fresh []string) []audit.Entry {
	if len(fresh) == 0 {
		return nil
	}
	type stat struct {
		users    map[string]struct{}
		requests int64
		first    time.Time
	}
	by := map[string]*stat{}
	for _, id := range fresh {
		by[id] = &stat{users: map[string]struct{}{}}
	}
	for _, a := range aggs {
		st := by[a.Service]
		if st == nil {
			continue
		}
		if a.UserAlias != "" {
			st.users[a.UserAlias] = struct{}{}
		}
		st.requests = min(st.requests+a.Requests, maxCounter)
		if st.first.IsZero() || a.Bucket.Before(st.first) {
			st.first = a.Bucket
		}
	}
	ids := append([]string(nil), fresh...)
	sort.Strings(ids)
	out := make([]audit.Entry, 0, len(ids))
	for _, id := range ids {
		st := by[id]
		name := names[id]
		if name == "" {
			name = id
		}
		out = append(out, audit.Entry{Actor: actor, SourceIP: ip, Action: "shadow_ai.new_service",
			Object: audit.Object{Type: "shadow_ai_service", ID: id}, Result: audit.ResultSuccess,
			Details: map[string]any{"service": id, "service_name": name, "users": len(st.users), "requests": st.requests,
				"first_seen": st.first.UTC().Format(time.RFC3339), "source": source,
				"window_days": int(NewServiceWindow / (24 * time.Hour))}})
	}
	return out
}

// systemActor — сервер управления (приём по syslog, очистка по сроку).
var systemActor = audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"}
