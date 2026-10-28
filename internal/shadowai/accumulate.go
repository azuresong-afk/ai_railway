package shadowai

import (
	"sort"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Итог учёта одной разобранной строки журнала.
type outcome int

const (
	outcomeMatched outcome = iota
	outcomeUnmatched
	outcomeOutdated
	outcomeExcluded
)

// accumulator копит сводки «час × сервис × псевдоним» по разобранным
// строкам: общая часть импорта файлом и приёма по syslog (задача 4.23).
// Исходный идентификатор пользователя превращается в псевдоним сразу и
// дальше не хранится.
type accumulator struct {
	catalog *Catalog
	// mac — ключ псевдонимов пользователей; nil — пользователи не учитываются.
	mac aisecCrypto.MAC
	// cutoff — час, раньше которого записи не сохраняются (срок хранения).
	cutoff  time.Time
	exclude Exclusions
	maxKeys int

	aggs     map[aggKey]*Aggregate
	services map[string]struct{}
	from, to time.Time
}

func newAccumulator(c *Catalog, mac aisecCrypto.MAC, cutoff time.Time, ex Exclusions, maxKeys int) *accumulator {
	return &accumulator{catalog: c, mac: mac, cutoff: cutoff, exclude: ex, maxKeys: maxKeys,
		aggs: map[aggKey]*Aggregate{}, services: map[string]struct{}{}}
}

// add учитывает строку. ErrTooManyKeys — новый ключ сверх предела: строка
// не учтена.
func (a *accumulator) add(rec record) (outcome, error) {
	host, ok := NormalizeHost(rec.host)
	var svc CatalogService
	if ok {
		svc, ok = a.catalog.Match(host)
	}
	if !ok {
		return outcomeUnmatched, nil
	}
	bucket := rec.time.Truncate(time.Hour)
	if bucket.Before(a.cutoff) {
		return outcomeOutdated, nil
	}
	k := aggKey{bucket: bucket.Unix(), service: svc.ID, kind: UserKindNone}
	if a.mac != nil && rec.userKind != UserKindNone {
		k.alias, k.kind = pseudonym(a.mac, rec.user), rec.userKind
	}
	if a.exclude.Excludes(k.service, k.alias) {
		return outcomeExcluded, nil
	}
	g := a.aggs[k]
	if g == nil {
		if len(a.aggs) >= a.maxKeys {
			return outcomeMatched, ErrTooManyKeys
		}
		g = &Aggregate{Bucket: bucket, Service: k.service, UserAlias: k.alias, UserKind: k.kind}
		a.aggs[k] = g
	}
	g.Requests = min(g.Requests+1, maxCounter)
	g.Bytes = min(g.Bytes+rec.bytes, maxCounter)
	a.services[svc.ID] = struct{}{}
	if a.from.IsZero() || rec.time.Before(a.from) {
		a.from = rec.time
	}
	if rec.time.After(a.to) {
		a.to = rec.time
	}
	return outcomeMatched, nil
}

// names — названия найденных сервисов из каталога (для оповещения о новом
// сервисе).
func (a *accumulator) names() map[string]string {
	out := make(map[string]string, len(a.services))
	for id := range a.services {
		out[id] = id
		if s, ok := a.catalog.ByID(id); ok {
			out[id] = s.Name
		}
	}
	return out
}

// sorted — сводки по часу, сервису и псевдониму.
func (a *accumulator) sorted() []Aggregate {
	return sortAggregates(a.aggs)
}

func sortAggregates(m map[aggKey]*Aggregate) []Aggregate {
	out := make([]Aggregate, 0, len(m))
	for _, a := range m {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Bucket.Equal(b.Bucket) {
			return a.Bucket.Before(b.Bucket)
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.UserAlias != b.UserAlias {
			return a.UserAlias < b.UserAlias
		}
		return a.UserKind < b.UserKind
	})
	return out
}
