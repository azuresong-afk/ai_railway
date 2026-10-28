package license

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Причины отказа в загрузке (license.rejected, ответ API).
const (
	ReasonFormat       = "format"
	ReasonSignature    = "signature"
	ReasonPurpose      = "purpose"
	ReasonSubkeyTerm   = "subkey_expired"
	ReasonRevoked      = "revoked"
	ReasonIssuedDate   = "issued_date"
	ReasonClock        = "clock"
	ReasonNotYetValid  = "not_yet_valid"
	ReasonExpired      = "expired"
	ReasonDuplicate    = "duplicate"
	ReasonStaleNumber  = "stale_number"
	ReasonStaleIssued  = "stale_issued"
	maxRejectFileBytes = MaxFileSize
)

// MaxFileSize — наибольший файл лицензии.
const MaxFileSize = aisecCrypto.MaxLicenseSize

// RejectReason — код причины отказа по ошибке проверки.
func RejectReason(err error) string {
	switch {
	case errors.Is(err, aisecCrypto.ErrEndorsementSignature), errors.Is(err, aisecCrypto.ErrLicenseSignature):
		return ReasonSignature
	case errors.Is(err, aisecCrypto.ErrEndorsementPurpose):
		return ReasonPurpose
	case errors.Is(err, aisecCrypto.ErrEndorsementExpired):
		return ReasonSubkeyTerm
	case errors.Is(err, aisecCrypto.ErrEndorsementRevoked):
		return ReasonRevoked
	case errors.Is(err, ErrIssuedDate):
		return ReasonIssuedDate
	}
	return ReasonFormat
}

// Rejected — отказ в загрузке с кодом причины.
type Rejected struct {
	Reason string
	// Current — номер загруженной лицензии (для причин duplicate и stale_*).
	Current uint64
	Err     error
}

func (e *Rejected) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "лицензия отклонена: " + e.Reason
}

func (e *Rejected) Unwrap() error { return e.Err }

// Upload проверяет файл лицензии на текущее время и сохраняет его, если это
// действительная лицензия новее загруженной (ADR-0026, п. 6). Нужна
// повторная проверка by.Confirm. И успех, и отказ пишутся в аудит без
// файла и подписи.
func (s *Service) Upload(ctx context.Context, by By, data []byte) (Info, error) {
	if by.Confirm == nil {
		return Info{}, ErrConfirmRequired
	}
	if err := by.Confirm(ctx); err != nil {
		return Info{}, err
	}
	cur, err := s.State(ctx)
	if err != nil {
		return Info{}, err
	}
	now := s.o.Clock().UTC()
	// Срок заверения — на время лицензии (с отметкой часов): перевод часов
	// назад не позволяет загрузить лицензию, подписанную истёкшим ключом.
	sg, verr := Verify(s.o.Provider, s.o.Vendor, data, cur.At)
	rej := &Rejected{Err: verr}
	if verr != nil {
		rej.Reason = RejectReason(verr)
	} else {
		l := sg.License
		switch {
		case now.Before(l.IssuedAt):
			rej.Reason = ReasonClock
		case now.Before(l.ValidFrom):
			rej.Reason = ReasonNotYetValid
		case cur.At.After(l.ValidUntil):
			// Время лицензии (с отметкой часов): перевод часов назад не
			// позволяет загрузить истёкшую.
			rej.Reason = ReasonExpired
		case cur.Number != 0 && l.Number == cur.Number:
			rej.Reason, rej.Current = ReasonDuplicate, cur.Number
		case cur.Number != 0 && l.Number < cur.Number:
			rej.Reason, rej.Current = ReasonStaleNumber, cur.Number
		case cur.Signed != nil && l.IssuedAt.Before(cur.Signed.License.IssuedAt):
			rej.Reason, rej.Current = ReasonStaleIssued, cur.Number
		default:
			rej = nil
		}
	}
	obj := audit.Object{Type: "license"}
	if rej == nil {
		l := sg.License
		obj.ID = strconv.FormatUint(l.Number, 10)
		rec := audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: "license.loaded", Object: obj, Result: audit.ResultSuccess,
			Details: map[string]any{"number": l.Number, "previous_number": cur.Number, "previous_state": cur.Phase,
				"type": l.Type, "organization": l.Licensee.Organization, "inn": l.Licensee.INN,
				"issued_at": l.IssuedAt.Format(time.RFC3339), "valid_from": l.ValidFrom.Format(time.RFC3339),
				"valid_until": l.ValidUntil.Format(time.RFC3339), "gateways_limit": l.Limits.Gateways,
				"applications_limit": l.Limits.Applications, "modules": l.Modules, "subkey_serial": sg.Endorsement.Serial,
				"fingerprint": sg.Fingerprint, "file_hash": sg.FileHash}}
		st := Stored{Number: l.Number, File: data, LoadedAt: now, LoadedBy: by.ref()}
		err := s.o.Store.Save(ctx, s.o.OrgID, st, rec)
		if err == nil {
			// Состояние — из хранилища: другой узел мог загрузить более новую.
			if rerr := s.Refresh(ctx); rerr != nil {
				s.mu.Lock()
				s.signed, s.stored, s.loaded = &sg, st, true
				s.mu.Unlock()
			}
			return s.Info(ctx)
		}
		if !errors.Is(err, ErrStale) {
			return Info{}, err
		}
		rej = &Rejected{Reason: ReasonStaleNumber, Err: err}
	}
	d := map[string]any{"reason": rej.Reason, "bytes": len(data)}
	if h, herr := s.o.Provider.Hasher(); herr == nil && len(data) <= maxRejectFileBytes {
		d["file_hash"] = hex.EncodeToString(h.Sum(data))
	}
	if sg.License != nil {
		d["number"], d["subkey_serial"] = sg.License.Number, sg.Endorsement.Serial
		obj.ID = strconv.FormatUint(sg.License.Number, 10)
	}
	if rej.Current != 0 {
		d["current_number"] = rej.Current
	}
	rec := audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: "license.rejected", Object: obj, Result: audit.ResultFailure, Details: d}
	if aerr := s.o.Store.Record(ctx, rec); aerr != nil {
		return Info{}, aerr
	}
	return Info{}, rej
}

// Info — сведения о лицензии для консоли (GET /api/v1/license).
type Info struct {
	State string `json:"state"`
	// Restricted — изменения конфигурации запрещены.
	Restricted bool `json:"restricted"`
	// ClockBehind — часы сервера раньше даты выдачи или отметки часов.
	ClockBehind bool `json:"clock_behind"`
	// Number — номер загруженной лицензии; 0 — «пилот по договору».
	Number        uint64     `json:"number"`
	Type          string     `json:"type,omitempty"`
	Licensee      *Licensee  `json:"licensee,omitempty"`
	IssuedAt      *time.Time `json:"issued_at,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ValidUntil    *time.Time `json:"valid_until,omitempty"`
	GraceUntil    *time.Time `json:"grace_until,omitempty"`
	DaysLeft      *int       `json:"days_left,omitempty"`
	GraceDaysLeft *int       `json:"grace_days_left,omitempty"`
	Limits        *Limits    `json:"limits,omitempty"`
	// Usage — текущее число шлюзов и приложений; nil — не посчитано.
	Usage *Usage `json:"usage,omitempty"`
	// Modules — включённые модули (без лицензии — все).
	Modules        []string   `json:"modules"`
	SubkeySerial   uint64     `json:"subkey_serial,omitempty"`
	SubkeyNotAfter *time.Time `json:"subkey_not_after,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	LoadedAt       *time.Time `json:"loaded_at,omitempty"`
}

func timeP(t time.Time) *time.Time {
	u := t.UTC()
	return &u
}

// Info — сведения о лицензии, её состоянии и использовании пределов.
func (s *Service) Info(ctx context.Context) (Info, error) {
	st, err := s.State(ctx)
	if err != nil {
		return Info{}, err
	}
	s.mu.Lock()
	stored := s.stored
	s.mu.Unlock()
	v := Info{State: st.Phase, Restricted: st.Restricted(), ClockBehind: st.ClockBehind, Number: st.Number, Modules: []string{}}
	if st.Number != 0 && !stored.LoadedAt.IsZero() {
		v.LoadedAt = timeP(stored.LoadedAt)
	}
	switch {
	case st.Phase == PhaseNone:
		v.Modules = append(v.Modules, Modules...)
	case st.Signed != nil:
		l, e := st.Signed.License, st.Signed.Endorsement
		lic, lim := l.Licensee, l.Limits
		dl, gl := st.DaysLeft(), st.GraceDaysLeft()
		v.Type, v.Licensee, v.Limits, v.Modules = l.Type, &lic, &lim, append(v.Modules, l.Modules...)
		v.IssuedAt, v.ValidFrom, v.ValidUntil, v.GraceUntil = timeP(l.IssuedAt), timeP(l.ValidFrom), timeP(l.ValidUntil), timeP(st.GraceUntil())
		v.DaysLeft, v.GraceDaysLeft = &dl, &gl
		v.SubkeySerial, v.SubkeyNotAfter, v.Fingerprint = e.Serial, timeP(e.NotAfter), st.Signed.Fingerprint
	}
	if s.o.Usage != nil {
		u, err := s.o.Usage(ctx)
		if err != nil {
			s.o.Logger.Error("лицензия: использование пределов не посчитано", "error", err)
		} else {
			v.Usage = &u
		}
	}
	return v, nil
}
