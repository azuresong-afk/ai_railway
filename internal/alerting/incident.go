package alerting

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Связь оповещений с инцидентами (ТЗ 5.7, 1.4 S4; задача 3.16 этапа 3,
// ADR-0020, п. 4–5). Движок не меняется: правила с признаком «инцидент»
// отмечаются обёрткой над txOps, а инцидент создаёт IncidentOpener пакета
// internal/incidents в той же транзакции приёма событий. Дедупликация
// автоматических инцидентов — по open_key оповещения: пока оповещение
// принимает срабатывания, они дополняют его инцидент.
//
// Порядок блокировок: сначала строки оповещений (FOR UPDATE), потом строка
// инцидента (FOR NO KEY UPDATE). Приём событий строку инцидента не
// блокирует: он только добавляет хронологию и ссылки.

// BuiltinCanaryLeak — канарейка системного промпта в ответе модели (DM-08,
// сценарий S4): оповещение и инцидент.
const BuiltinCanaryLeak = "threshold.canary_leak"

// autoIncident — встроенные правила, оповещения которых сразу становятся
// инцидентами; значение — категория инцидента (ТЗ 5.7).
var autoIncident = map[string]string{BuiltinCanaryLeak: "system_prompt_leak"}

// AutoIncidentCategory — категория автоматического инцидента встроенного
// правила; false — правило инцидентов не создаёт.
func AutoIncidentCategory(builtinKey string) (string, bool) {
	c, ok := autoIncident[builtinKey]
	return c, ok
}

// incidentRules — встроенные правила, создающие инциденты.
func incidentRules() []Rule {
	return []Rule{
		{BuiltinKey: BuiltinCanaryLeak, Kind: KindThreshold, Name: "Утечка системного промпта",
			Description: "DM-08: в ответе модели найдена канарейка системного промпта (ТЗ 1.4, S4). " +
				"Оповещение и инцидент на приложение, пока оповещение не закрыто; новые срабатывания дополняют инцидент, " +
				"утечка после закрытия сразу открывает новый.",
			// Без окна подавления: каждая утечка после закрытия инцидента —
			// новое оповещение и новый инцидент (сценарий S4).
			Enabled: true, Severity: "critical", Condition: Condition{Filter: canonical(`threat = "DM-08" and detector = "canary"`)},
			GroupBy: []string{"app"}, SuppressMinutes: 0, Recipients: Recipients{Roles: []string{}, Users: []string{}}},
	}
}

// IncidentOpener — инциденты по оповещениям в транзакции приёма событий.
// tx — транзакция PostgreSQL; у хранилища Memory — nil.
type IncidentOpener interface {
	// OpenFromAlert создаёт инцидент категории category по оповещению a со
	// ссылками refs и возвращает его ID.
	OpenFromAlert(ctx context.Context, tx pgx.Tx, a Alert, refs []EventRef, category string) (string, error)
	// NoteAlert — новые срабатывания оповещения, уже связанного с
	// инцидентом: запись хронологии и ссылки на события.
	NoteAlert(ctx context.Context, tx pgx.Tx, incidentID string, a Alert, refs []EventRef) error
}

// incidentHit — срабатывание правила с признаком «инцидент».
type incidentHit struct {
	rule     Rule
	key      string
	refs     []EventRef
	category string
}

// linkOps — txOps, запоминающий срабатывания правил с признаком «инцидент».
type linkOps struct {
	txOps
	hits []incidentHit
}

func (o *linkOps) raise(ctx context.Context, r *Rule, t *Trigger) error {
	if err := o.txOps.raise(ctx, r, t); err != nil {
		return err
	}
	if c, ok := autoIncident[r.BuiltinKey]; ok {
		o.hits = append(o.hits, incidentHit{rule: r.clone(), key: t.Key, refs: slices.Clone(t.Events), category: c})
	}
	return nil
}

// incidentHook — events.IngestHook: движок оповещений и инциденты по их
// срабатываниям в одной транзакции.
type incidentHook struct {
	s *PGStore
	o IncidentOpener
}

// WithIncidents — обработчик приёма событий: правила «порог», «новое»,
// счёт «частоты» и DM-38 (как OnIngest) и инциденты по оповещениям правил с признаком «инцидент».
func (s *PGStore) WithIncidents(o IncidentOpener) events.IngestHook {
	return incidentHook{s: s, o: o}
}

// OnIngest — см. events.IngestHook.
func (h incidentHook) OnIngest(ctx context.Context, tx pgx.Tx, gatewayID string, accepted []*events.Event) error {
	// Те же шаги, что в PGStore.OnIngest (меняются вместе с ним), но через
	// linkOps: срабатывания правил с признаком «инцидент» запоминаются.
	ops := &linkOps{txOps: pgOps{s: h.s, tx: tx}}
	skipped := func(err error) {
		h.s.logger.Error("оповещения: правило пропущено", "error", err)
	}
	if err := process(ctx, ops, gatewayID, accepted, skipped); err != nil {
		return err
	}
	if err := countFrequency(ctx, pgOps{s: h.s, tx: tx}, time.Now(), gatewayID, accepted, skipped); err != nil {
		return err
	}
	if err := processAuthFailures(ctx, ops, accepted); err != nil {
		return err
	}
	for _, hit := range ops.hits {
		a, err := scanAlert(tx.QueryRow(ctx, `SELECT `+alertCols+` FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
			WHERE a.org_id = $1 AND a.rule_id = $2 AND a.open_key = $3 FOR UPDATE OF a`, h.s.orgID, hit.rule.ID, hit.key))
		if errors.Is(err, ErrNotFound) {
			// Срабатывание ушло в окно подавления после закрытия.
			continue
		}
		if err != nil {
			return err
		}
		if a.IncidentID != "" {
			if err := h.o.NoteAlert(ctx, tx, a.IncidentID, a, hit.refs); err != nil {
				return err
			}
			continue
		}
		id, err := h.o.OpenFromAlert(ctx, tx, a, hit.refs, hit.category)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alerts SET incident_id = $3, updated_at = now() WHERE org_id = $1 AND id = $2`,
			h.s.orgID, a.ID, id); err != nil {
			return dbErr(err)
		}
	}
	return nil
}

// AlertForIncidentTx — оповещение под блокировкой строки и ссылки на его
// события: создание инцидента из оповещения или связь с существующим.
func (s *PGStore) AlertForIncidentTx(ctx context.Context, tx pgx.Tx, orgID, id string) (Alert, []EventRef, error) {
	a, err := scanAlert(tx.QueryRow(ctx, `SELECT `+alertCols+` FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.org_id = $1 AND a.id = $2 FOR UPDATE OF a`, orgID, id))
	if err != nil {
		return Alert{}, nil, err
	}
	rows, err := tx.Query(ctx, `SELECT event_id::text, event_ts FROM alert_events WHERE alert_id = $1 ORDER BY event_ts, event_id`, id)
	if err != nil {
		return Alert{}, nil, err
	}
	refs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (EventRef, error) {
		var e EventRef
		err := r.Scan(&e.ID, &e.TS)
		e.TS = e.TS.UTC()
		return e, err
	})
	return a, refs, err
}

// LinkIncidentTx связывает оповещение, заблокированное AlertForIncidentTx, с
// инцидентом. Уже связанное с другим инцидентом — ErrLinked.
func (s *PGStore) LinkIncidentTx(ctx context.Context, tx pgx.Tx, orgID, alertID, incidentID string) error {
	tag, err := tx.Exec(ctx, `UPDATE alerts SET incident_id = $3, updated_at = now()
		WHERE org_id = $1 AND id = $2 AND incident_id IS NULL`, orgID, alertID, incidentID)
	if err != nil {
		return dbErr(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrLinked
	}
	return nil
}

// ErrLinked — оповещение уже связано с другим инцидентом.
var ErrLinked = errors.New("оповещение уже связано с другим инцидентом")

// IncidentAlerts — оповещения, связанные с инцидентом (не больше MaxIncidentAlerts).
func (s *PGStore) IncidentAlerts(ctx context.Context, orgID, incidentID string) ([]Alert, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return incidentAlerts(ctx, s.db, orgID, incidentID)
}

// IncidentAlertsTx — IncidentAlerts в транзакции tx (согласованная карточка).
func (s *PGStore) IncidentAlertsTx(ctx context.Context, tx pgx.Tx, orgID, incidentID string) ([]Alert, error) {
	return incidentAlerts(ctx, tx, orgID, incidentID)
}

func incidentAlerts(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}, orgID, incidentID string) ([]Alert, error) {
	rows, err := q.Query(ctx, `SELECT `+alertCols+` FROM alerts a JOIN alert_rules r ON r.id = a.rule_id
		WHERE a.org_id = $1 AND a.incident_id = $2 ORDER BY a.created_at, a.id LIMIT $3`, orgID, incidentID, MaxIncidentAlerts)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) { return scanAlert(r) })
}

// MaxIncidentAlerts — оповещений, связанных с одним инцидентом.
const MaxIncidentAlerts = 100

// CloseForIncidentTx закрывает незакрытые оповещения инцидента вместе с
// ним: история, alert.status_changed в аудит. Открытое оповещение
// закрытого инцидента иначе дополняло бы инцидент, который уже не меняется.
// Ограничения closeAllowed действуют и здесь (3В30 ревью 3.r4): субъект
// оповещения безопасности и токен API не закрывают его через инцидент —
// закрытие инцидента отклоняется целиком. Возвращает ID закрытых оповещений.
func (s *PGStore) CloseForIncidentTx(ctx context.Context, tx pgx.Tx, orgID, incidentID string, by By, comment string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT a.id::text, a.status, a.rule_id::text, a.severity, a.kind, a.dedup_key FROM alerts a
		WHERE a.org_id = $1 AND a.incident_id = $2 AND a.status <> 'closed' ORDER BY a.id FOR UPDATE`, orgID, incidentID)
	if err != nil {
		return nil, err
	}
	type open struct{ id, status, rule, severity, kind, key string }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (open, error) {
		var o open
		err := r.Scan(&o.id, &o.status, &o.rule, &o.severity, &o.kind, &o.key)
		return o, err
	})
	if err != nil {
		return nil, err
	}
	for _, a := range list {
		if err := closeAllowed(&Alert{Kind: a.kind, DedupKey: a.key}, by, StatusClosed); err != nil {
			return nil, err
		}
	}
	var closed []string
	for _, a := range list {
		u, err := s.ids.New()
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'closed', open_key = NULL, closed_at = $3, closed_by = $4,
			updated_at = $3 WHERE org_id = $1 AND id = $2`, orgID, a.id, now, by.ref()); err != nil {
			return nil, dbErr(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO alert_history (id, alert_id, at, actor, from_status, to_status, comment)
			VALUES ($1, $2, $3, $4, $5, 'closed', $6)`, u.String(), a.id, now, by.ref(), a.status, comment); err != nil {
			return nil, dbErr(err)
		}
		if err := s.audit.RecordTx(ctx, tx, closeEntry(by, a.id, a.status, a.rule, a.severity, incidentID)); err != nil {
			return nil, err
		}
		closed = append(closed, a.id)
	}
	return closed, nil
}

func closeEntry(by By, alertID, from, ruleID, severity, incidentID string) audit.Entry {
	return by.entry("alert.status_changed", "alert", alertID, map[string]any{"from": from, "to": StatusClosed,
		"rule_id": ruleID, "severity": severity, "comment": true, "incident_id": incidentID})
}

// IngestWithIncidents — Ingest с инцидентами по оповещениям правил с
// признаком «инцидент» (хранилище Memory, tx — nil). Хранилища не
// блокируются одновременно: связь ставится после создания инцидента.
func (m *Memory) IngestWithIncidents(ctx context.Context, gatewayID string, evs []*events.Event, o IncidentOpener) error {
	m.mu.Lock()
	if err := m.takeErr(); err != nil {
		m.mu.Unlock()
		return err
	}
	// Те же шаги, что в Memory.Ingest.
	ops := &linkOps{txOps: memOps{m}}
	err := process(ctx, ops, gatewayID, evs, nil)
	if err == nil {
		err = countFrequency(ctx, memOps{m}, m.now(), gatewayID, evs, nil)
	}
	if err == nil {
		err = processAuthFailures(ctx, ops, evs)
	}
	type pending struct {
		a    Alert
		refs []EventRef
		cat  string
	}
	var todo []pending
	for _, hit := range ops.hits {
		for _, a := range m.alerts {
			if a.RuleID == hit.rule.ID && a.Open && a.DedupKey == hit.key {
				c := a.clone()
				c.RuleName = hit.rule.Name
				todo = append(todo, pending{a: c, refs: hit.refs, cat: hit.category})
			}
		}
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	for _, p := range todo {
		if p.a.IncidentID != "" {
			if err := o.NoteAlert(ctx, nil, p.a.IncidentID, p.a, p.refs); err != nil {
				return err
			}
			continue
		}
		id, err := o.OpenFromAlert(ctx, nil, p.a, p.refs, p.cat)
		if err != nil {
			return err
		}
		if err := m.LinkIncident(p.a.OrgID, p.a.ID, id); err != nil {
			return err
		}
	}
	return nil
}

// AlertForIncident — оповещение и ссылки на его события (Memory).
func (m *Memory) AlertForIncident(orgID, id string) (Alert, []EventRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.alerts[id]
	if !ok || a.OrgID != orgID {
		return Alert{}, nil, ErrNotFound
	}
	c := a.clone()
	c.RuleName = m.rules[a.RuleID].Name
	return c, slices.Clone(m.refs[id]), nil
}

// LinkIncident — см. LinkIncidentTx (Memory).
func (m *Memory) LinkIncident(orgID, alertID, incidentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.alerts[alertID]
	if !ok || a.OrgID != orgID {
		return ErrNotFound
	}
	if a.IncidentID != "" {
		return ErrLinked
	}
	a.IncidentID, a.UpdatedAt = incidentID, m.now()
	return nil
}

// IncidentAlerts — см. PGStore.IncidentAlerts (Memory).
func (m *Memory) IncidentAlerts(_ context.Context, orgID, incidentID string) ([]Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Alert
	for _, a := range m.alerts {
		if a.OrgID == orgID && a.IncidentID == incidentID {
			c := a.clone()
			c.RuleName = m.rules[a.RuleID].Name
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Alert) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	if len(out) > MaxIncidentAlerts {
		out = out[:MaxIncidentAlerts]
	}
	return out, nil
}

// CanCloseForIncident — проверка closeAllowed по незакрытым оповещениям
// инцидента до его закрытия (Memory: хранилище инцидентов в памяти не
// транзакционно и проверяет заранее).
func (m *Memory) CanCloseForIncident(orgID, incidentID string, by By) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.alerts {
		if a.OrgID == orgID && a.IncidentID == incidentID && a.Status != StatusClosed {
			if err := closeAllowed(a, by, StatusClosed); err != nil {
				return err
			}
		}
	}
	return nil
}

// CloseForIncident — см. CloseForIncidentTx (Memory).
func (m *Memory) CloseForIncident(orgID, incidentID string, by By, comment string) ([]string, error) {
	if err := m.CanCloseForIncident(orgID, incidentID, by); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var closed []string
	for _, a := range m.alerts {
		if a.OrgID != orgID || a.IncidentID != incidentID || a.Status == StatusClosed {
			continue
		}
		now := m.now()
		from := a.Status
		a.Status, a.Open, a.ClosedAt, a.ClosedBy, a.UpdatedAt = StatusClosed, false, now, by.ref(), now
		m.history[a.ID] = append(m.history[a.ID], History{ID: m.newID(), AlertID: a.ID, At: now, Actor: by.ref(),
			From: from, To: StatusClosed, Comment: comment})
		m.records = append(m.records, closeEntry(by, a.ID, from, a.RuleID, a.Severity, incidentID))
		closed = append(closed, a.ID)
	}
	slices.Sort(closed)
	return closed, nil
}
