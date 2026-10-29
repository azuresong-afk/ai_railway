package shadowai

import (
	"context"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Пределы импорта (ADR-0027, п. 5).
const (
	DefaultMaxLines        = 10_000_000
	DefaultMaxKeys         = 500_000
	DefaultMaxDecompressed = 1 << 30
	// MaxErrorLines — сколько номеров ошибочных строк показывается.
	MaxErrorLines = 20
	// maxCounter — предел суммы счётчика (защита от переполнения bigint).
	maxCounter = 1 << 62
	// ctxCheckEvery — как часто проверяется отмена (по строкам).
	ctxCheckEvery = 4096
)

// Ошибки импорта целиком (не строки).
var (
	ErrTooManyLines  = errors.New("в журнале больше допустимого числа строк")
	ErrTooManyKeys   = errors.New("в журнале слишком много разных сочетаний сервиса, пользователя и часа")
	ErrTooLarge      = errors.New("журнал после распаковки больше допустимого размера")
	ErrEmpty         = errors.New("журнал пуст")
	ErrNoCatalog     = errors.New("каталог доменов не загружен")
	ErrBusy          = errors.New("уже идёт другой импорт")
	ErrDuplicate     = errors.New("этот файл уже импортирован")
	ErrBadFormat     = errors.New("неизвестный формат журнала")
	ErrStaleCatalog  = errors.New("версия каталога не больше загруженной")
	ErrNotSetUp      = errors.New("первичная настройка не выполнена")
	ErrConfirmNeeded = errors.New("сокращение срока хранения требует повторной проверки")
)

// Limits — пределы одного импорта; нули — умолчания.
type Limits struct {
	MaxLine         int
	MaxLines        int64
	MaxKeys         int
	MaxDecompressed int64
}

func (l Limits) withDefaults() Limits {
	if l.MaxLine <= 0 {
		l.MaxLine = DefaultMaxLine
	}
	if l.MaxLines <= 0 {
		l.MaxLines = DefaultMaxLines
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = DefaultMaxKeys
	}
	if l.MaxDecompressed <= 0 {
		l.MaxDecompressed = DefaultMaxDecompressed
	}
	return l
}

// Aggregate — счётчики сервиса, пользователя и часа.
type Aggregate struct {
	Bucket    time.Time
	Service   string
	UserAlias string
	UserKind  string
	Requests  int64
	Bytes     int64
}

// ImportResult — итог разбора журнала без содержимого строк.
type ImportResult struct {
	Format string `json:"format"`
	// Lines — строк в файле (пустые и заголовок CSV не считаются).
	Lines     int64 `json:"lines"`
	Matched   int64 `json:"matched"`
	Unmatched int64 `json:"unmatched"`
	Errors    int64 `json:"errors"`
	// Outdated — сопоставленные строки старше срока хранения: не сохранены.
	Outdated int64 `json:"outdated"`
	// Excluded — сопоставленные строки исключённых пользователей и сервисов:
	// не сохранены (задача 4.23).
	Excluded int64 `json:"excluded"`
	// ErrorLines — первые номера ошибочных строк (с 1), без содержимого.
	ErrorLines []int64 `json:"error_lines"`
	// From и To — время первой и последней сопоставленной записи.
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
	// UsersPseudonymized — пользователи сохранены псевдонимами; false — ключа
	// псевдонимов нет, пользователи не учтены (ADR-0027, п. 6).
	UsersPseudonymized bool `json:"users_pseudonymized"`
	// SHA256 — хеш файла (после распаковки), по нему отклоняется повтор.
	SHA256 string `json:"sha256"`
	// Services — сколько разных сервисов найдено.
	Services   int         `json:"services"`
	Aggregates []Aggregate `json:"-"`
	// ServiceNames — названия найденных сервисов по каталогу: для записи
	// аудита о новом сервисе (DM-37).
	ServiceNames map[string]string `json:"-"`
}

// importInput — всё, что нужно для разбора одного файла.
type importInput struct {
	format  string
	catalog *Catalog
	// mac — ключ псевдонимов пользователей; nil — пользователи не учитываются.
	mac    aisecCrypto.MAC
	hasher aisecCrypto.Hasher
	loc    *time.Location
	now    time.Time
	// cutoff — час, раньше которого записи не сохраняются (срок хранения).
	cutoff  time.Time
	exclude Exclusions
	limits  Limits
}

type aggKey struct {
	bucket  int64
	service string
	alias   string
	kind    string
}

// limitReader считает прочитанные байты и отказывает сверх max.
type limitReader struct {
	r   io.Reader
	n   int64
	max int64
	h   hash.Hash
}

func (l *limitReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.max {
		return 0, ErrTooLarge
	}
	if n > 0 {
		_, _ = l.h.Write(p[:n]) //nolint:gosec // G104: hash.Hash.Write не возвращает ошибку
	}
	return n, err
}

// pseudonym — псевдоним пользователя тем же механизмом, что в событиях
// шлюза (ТЗ 5.5): HMAC идентификатора, первые 16 байт в hex.
func pseudonym(mac aisecCrypto.MAC, id string) string {
	return hex.EncodeToString(mac.Sum([]byte(id))[:16])
}

// aggregate разбирает журнал построчно и считает агрегаты. Ошибка
// возвращается только для файла целиком; ошибки строк — в счётчике.
func aggregate(ctx context.Context, r io.Reader, in importInput) (ImportResult, error) {
	lim := in.limits.withDefaults()
	p, err := newParser(in.format, timeBounds{loc: in.loc, max: in.now.Add(24 * time.Hour)})
	if err != nil {
		return ImportResult{}, ErrBadFormat
	}
	lr := &limitReader{r: r, max: lim.MaxDecompressed, h: in.hasher.New()}
	lines := newLineReader(lr, lim.MaxLine)
	res := ImportResult{Format: in.format, ErrorLines: []int64{}, UsersPseudonymized: in.mac != nil}
	acc := newAccumulator(in.catalog, in.mac, in.cutoff, in.exclude, lim.MaxKeys)
	var lineNo int64
	lineErr := func() {
		res.Errors++
		if len(res.ErrorLines) < MaxErrorLines {
			res.ErrorLines = append(res.ErrorLines, lineNo)
		}
	}
	for {
		line, long, err := lines.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ImportResult{}, err
		}
		lineNo++
		if lineNo > lim.MaxLines {
			return ImportResult{}, ErrTooManyLines
		}
		if lineNo%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return ImportResult{}, err
			}
		}
		if long {
			res.Lines++
			lineErr()
			continue
		}
		rec, skip, err := p.parse(line)
		if errors.Is(err, ErrHeader) {
			return ImportResult{}, ErrHeader
		}
		if skip {
			continue
		}
		res.Lines++
		if err != nil {
			lineErr()
			continue
		}
		o, err := acc.add(rec)
		if err != nil {
			return ImportResult{}, err
		}
		switch o {
		case outcomeMatched:
			res.Matched++
		case outcomeUnmatched:
			res.Unmatched++
		case outcomeOutdated:
			res.Outdated++
		case outcomeExcluded:
			res.Excluded++
		}
	}
	if lr.n == 0 {
		return ImportResult{}, ErrEmpty
	}
	res.SHA256 = hex.EncodeToString(lr.h.Sum(nil))
	res.Services = len(acc.services)
	if !acc.from.IsZero() {
		f, t := acc.from.UTC(), acc.to.UTC()
		res.From, res.To = &f, &t
	}
	res.Aggregates = acc.sorted()
	res.ServiceNames = acc.names()
	return res, nil
}
