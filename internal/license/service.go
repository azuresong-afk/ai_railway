package license

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Ошибки хранилища и загрузки.
var (
	// ErrNoLicense — лицензия не загружалась ни разу.
	ErrNoLicense = errors.New("лицензия не загружена")
	// ErrStale — номер не больше загруженного (параллельная загрузка).
	ErrStale = errors.New("лицензия: номер не больше загруженного")
	// ErrConfirmRequired — загрузка без повторной проверки (не из сессии консоли).
	ErrConfirmRequired = errors.New("лицензия: загрузка — только в консоли с повторной проверкой")
)

// Коды отказа в изменении (ответ API — 403 с этим кодом).
const (
	CodeRestricted = "license_restricted"
	CodeModule     = "license_module"
	CodeLimit      = "license_limit"
)

// Denied — изменение запрещено лицензией: код и причина для пользователя.
type Denied struct {
	Code    string
	Message string
}

func (d *Denied) Error() string { return "лицензия: " + d.Message }

// Stored — лицензия в хранилище.
type Stored struct {
	Number   uint64
	File     []byte
	LoadedAt time.Time
	LoadedBy string
}

// Store — хранилище лицензий (PGStore, Memory). Таблица лицензий только
// дополняется: вернуться к «пилоту по договору» нельзя.
type Store interface {
	// Current — лицензия с наибольшим номером; ErrNoLicense — не загружалась.
	Current(ctx context.Context, orgID string) (Stored, error)
	// Save добавляет лицензию, если её номер больше всех загруженных (иначе
	// ErrStale), и пишет rec той же транзакцией.
	Save(ctx context.Context, orgID string, s Stored, rec audit.Entry) error
	// Record пишет запись аудита вне транзакции данных (отказ в загрузке).
	Record(ctx context.Context, rec audit.Entry) error
	// AdvanceClock поднимает отметку часов до t (только вверх) и возвращает
	// её значение.
	AdvanceClock(ctx context.Context, orgID string, t time.Time) (time.Time, error)
}

// Usage — использование пределов.
type Usage struct {
	// Gateways — действующие (зарегистрированные, не отозванные) шлюзы.
	Gateways int `json:"gateways"`
	// Applications — приложения не в архиве.
	Applications int `json:"applications"`
}

// Options — зависимости сервиса.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	OrgID    string
	Clock    func() time.Time
	Logger   *slog.Logger
	// Usage — текущее число шлюзов и приложений; nil — пределы не
	// проверяются (сервер без реестра шлюзов и приложений).
	Usage func(ctx context.Context) (Usage, error)
	// Vendor — ключ производителя; nil — встроенный в сборку.
	Vendor aisecCrypto.Verifier
}

// By — субъект загрузки.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Confirm — повторная проверка паролем или кодом TOTP (обязательна).
	Confirm func(ctx context.Context) error
}

func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// Service — лицензия установки: проверка, состояние, загрузка, ограничения.
type Service struct {
	o Options

	mu        sync.Mutex
	loaded    bool
	signed    *Signed
	stored    Stored
	highWater time.Time
}

// RefreshInterval — период повторной проверки лицензии и отметки часов.
const RefreshInterval = time.Minute

// storeTimeout — предел одного обращения к хранилищу из проверки запроса.
const storeTimeout = 3 * time.Second

// New создаёт сервис. Лицензия читается из хранилища при первом обращении
// (или Refresh) и проверяется заново.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil {
		return nil, errors.New("лицензия: нет хранилища или криптопрофиля")
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Vendor == nil {
		v, err := VendorVerifier(o.Provider)
		if err != nil {
			return nil, err
		}
		o.Vendor = v
	}
	return &Service{o: o}, nil
}

// Refresh поднимает отметку часов, читает текущую лицензию и проверяет её
// заново без срока заверения (ADR-0026, п. 2). Не прошедшая проверку
// лицензия даёт состояние invalid, причина — в техническом журнале.
func (s *Service) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked(ctx)
}

func (s *Service) refreshLocked(ctx context.Context) error {
	hw, err := s.o.Store.AdvanceClock(ctx, s.o.OrgID, s.o.Clock().UTC())
	if err != nil {
		return err
	}
	st, err := s.o.Store.Current(ctx, s.o.OrgID)
	switch {
	case errors.Is(err, ErrNoLicense):
		s.signed, s.stored = nil, Stored{}
	case err != nil:
		return err
	default:
		// Та же лицензия, что уже проверена: повторная проверка подписи раз в
		// минуту не нужна, файл в БД сверяется побайтно.
		if !s.loaded || s.stored.Number != st.Number || string(s.stored.File) != string(st.File) || s.signed == nil {
			sg, verr := Verify(s.o.Provider, s.o.Vendor, st.File, time.Time{})
			if verr != nil || sg.License.Number != st.Number {
				if !s.loaded || s.signed != nil || s.stored.Number != st.Number {
					s.o.Logger.Error("лицензия: загруженная лицензия не прошла проверку подписи", "class", "integrity",
						"number", st.Number, "error", verr)
				}
				s.signed = nil
			} else {
				s.signed = &sg
			}
		}
		s.stored = st
	}
	s.highWater, s.loaded = hw, true
	return nil
}

// Run повторяет Refresh каждые interval, пока не отменён ctx.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = RefreshInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.Refresh(rctx)
		cancel()
		if err != nil && ctx.Err() == nil {
			s.o.Logger.Error("лицензия: состояние не обновлено", "class", "status", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// State — состояние лицензии сейчас. Если лицензия ещё не читалась,
// читает её; сбой хранилища — ошибка (изменяющий запрос получит 503).
func (s *Service) State(ctx context.Context) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		rctx, cancel := context.WithTimeout(ctx, storeTimeout)
		err := s.refreshLocked(rctx)
		cancel()
		if err != nil {
			return State{}, err
		}
	}
	return Evaluate(s.signed, s.stored.Number, s.o.Clock(), s.highWater), nil
}

func restrictedMessage(st State) string {
	if st.Phase == PhaseInvalid {
		return "Загруженная лицензия не прошла проверку подписи: изменения конфигурации запрещены. " +
			"Загрузите действующую лицензию в разделе «Администрирование → Лицензия»."
	}
	return fmt.Sprintf("Срок лицензии № %d истёк %s, льготный период закончился: изменения конфигурации запрещены. "+
		"Трафик, просмотр и выгрузки работают. Загрузите новую лицензию в разделе «Администрирование → Лицензия».",
		st.Signed.License.Number, st.Signed.License.ValidUntil.Format("02.01.2006"))
}

// CheckMutation — проверка изменяющего запроса (ADR-0026, п. 5): после
// льготного периода и при недействительной лицензии — отказ; модуль module
// (пусто — не модуль) должен быть включён в лицензию.
func (s *Service) CheckMutation(ctx context.Context, module string) error {
	st, err := s.State(ctx)
	if err != nil {
		return err
	}
	if st.Restricted() {
		return &Denied{Code: CodeRestricted, Message: restrictedMessage(st)}
	}
	if module != "" && !st.ModuleEnabled(module) {
		return moduleDenied(st, module)
	}
	return nil
}

func moduleDenied(st State, module string) *Denied {
	return &Denied{Code: CodeModule, Message: fmt.Sprintf("Модуль «%s» не входит в лицензию № %d: изменения в нём недоступны, "+
		"просмотр данных работает. Чтобы включить модуль, загрузите лицензию с ним.", ModuleTitle(module), st.Number)}
}

// CheckModule — проверка только модуля для маршрута из списка исключений
// запрета изменений (ADR-0026, п. 5): после льготного периода модули берутся
// из последней проверенной лицензии, у недействительной модулей нет; без
// лицензии доступны все.
func (s *Service) CheckModule(ctx context.Context, module string) error {
	st, err := s.State(ctx)
	if err != nil || module == "" || st.Phase == PhaseNone {
		return err
	}
	if st.Signed != nil && st.Signed.License.HasModule(module) {
		return nil
	}
	return moduleDenied(st, module)
}

// limit — предел шлюзов или приложений проверенной лицензии, в том числе
// после льготного периода (4В16 ревью 4.r2: прежде в restricted предела не
// было); 0 — нет предела или нет проверенной лицензии.
func (s *Service) limit(ctx context.Context, pick func(Limits) int) (State, int, Usage, error) {
	st, err := s.State(ctx)
	if err != nil || st.Signed == nil || s.o.Usage == nil {
		return st, 0, Usage{}, err
	}
	n := pick(st.Signed.License.Limits)
	if n == 0 {
		return st, 0, Usage{}, nil
	}
	u, err := s.o.Usage(ctx)
	return st, n, u, err
}

// CheckGateway — можно ли зарегистрировать новый шлюз (повторная
// регистрация действующего не проверяется): действующих меньше предела.
// Регистрация идёт мимо проверки маршрутизатора, поэтому при
// недействительной лицензии (пределов не прочесть) — отказ (4В16 ревью 4.r2).
func (s *Service) CheckGateway(ctx context.Context) error {
	st, n, u, err := s.limit(ctx, func(l Limits) int { return l.Gateways })
	if err == nil && st.Phase == PhaseInvalid {
		return &Denied{Code: CodeRestricted, Message: restrictedMessage(st)}
	}
	if err != nil || n == 0 {
		return err
	}
	if u.Gateways >= n {
		return &Denied{Code: CodeLimit, Message: fmt.Sprintf("Лицензия № %d разрешает %d действующих шлюзов, зарегистрировано %d: "+
			"новый шлюз не зарегистрирован, токен не погашен. Отзовите неиспользуемый шлюз или загрузите лицензию с большим пределом.",
			st.Number, n, u.Gateways)}
	}
	return nil
}

// CheckApplication — можно ли создать приложение: приложений не в архиве
// меньше предела.
func (s *Service) CheckApplication(ctx context.Context) error {
	st, n, u, err := s.limit(ctx, func(l Limits) int { return l.Applications })
	if err != nil || n == 0 {
		return err
	}
	if u.Applications >= n {
		return &Denied{Code: CodeLimit, Message: fmt.Sprintf("Лицензия № %d разрешает %d приложений, создано %d: новое приложение "+
			"не создано. Переведите неиспользуемое приложение в архив или загрузите лицензию с большим пределом.", st.Number, n, u.Applications)}
	}
	return nil
}
