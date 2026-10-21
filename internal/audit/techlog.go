package audit

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/store"
)

// TechKind — вид записи журнала технического состояния (РСБ.7).
type TechKind string

const (
	TechStart TechKind = "start" // запуск компонента
	TechStop  TechKind = "stop"  // остановка компонента
	TechInit  TechKind = "init"  // инициализация (миграции, ключи, самотест)
	TechState TechKind = "state" // состояние компонента или интерфейса
	TechError TechKind = "error" // ошибка или сбой
	TechLoad  TechKind = "load"  // загрузка: запросы, очередь, хранилище
)

// Level — важность записи.
type Level string

const (
	LevelInfo     Level = "info"
	LevelWarning  Level = "warning"
	LevelError    Level = "error"
	LevelCritical Level = "critical"
)

// ErrorClass — классификация ошибок и сбоев (РСБ.2, РСБ.7).
type ErrorClass string

const (
	ClassConfig    ErrorClass = "config"    // неверная конфигурация
	ClassDB        ErrorClass = "db"        // СУБД
	ClassNetwork   ErrorClass = "network"   // сеть и TLS
	ClassProvider  ErrorClass = "provider"  // провайдер LLM
	ClassIntegrity ErrorClass = "integrity" // целостность, цепочка аудита
	ClassCrypto    ErrorClass = "crypto"    // криптопрофиль
	ClassInternal  ErrorClass = "internal"  // внутренняя ошибка
)

const maxTechMessage = 1024

var componentRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// TechEntry — запись журнала технического состояния. В Message и Details
// не передаются секреты и содержимое запросов и ответов.
type TechEntry struct {
	OrgID     string // пусто — организация по умолчанию
	Component string // например, «server», «gateway», «audit»
	Kind      TechKind
	Level     Level
	Class     ErrorClass // обязателен для Kind = error, иначе пусто
	Message   string
	Details   any
}

func (e *TechEntry) validate() error {
	if !componentRe.MatchString(e.Component) {
		return errors.New("имя компонента: строчная латиница, цифры, «-», «_», до 32 символов")
	}
	switch e.Kind {
	case TechStart, TechStop, TechInit, TechState, TechError, TechLoad:
	default:
		return errors.New("неизвестный вид записи")
	}
	switch e.Level {
	case LevelInfo, LevelWarning, LevelError, LevelCritical:
	default:
		return errors.New("неизвестная важность")
	}
	switch e.Class {
	case "":
		if e.Kind == TechError {
			return errors.New("ошибка без классификации")
		}
	case ClassConfig, ClassDB, ClassNetwork, ClassProvider, ClassIntegrity, ClassCrypto, ClassInternal:
	default:
		return errors.New("неизвестный класс ошибки")
	}
	if e.Message == "" {
		return errors.New("пустое сообщение")
	}
	// Текст ошибки может содержать данные извне — нормализуется, а не отклоняется.
	e.Message = cleanText(e.Message, maxTechMessage)
	if e.OrgID != "" {
		if _, err := store.ParseUUID(e.OrgID); err != nil {
			return fmt.Errorf("ID организации: %w", err)
		}
	}
	return nil
}

// Tech пишет запись в журнал технического состояния (РСБ.7).
func (l *Log) Tech(ctx context.Context, e TechEntry) error {
	ctx, cancel := withTimeout(ctx, writeTimeout)
	defer cancel()
	return l.inTx(ctx, func(tx pgx.Tx) error { return l.techTx(ctx, tx, e) })
}

func (l *Log) techTx(ctx context.Context, tx pgx.Tx, e TechEntry) error {
	if err := e.validate(); err != nil {
		return fmt.Errorf("журнал технического состояния: %w", err)
	}
	details, err := CanonicalDetails(e.Details)
	if err != nil {
		return fmt.Errorf("журнал технического состояния: %w", err)
	}
	org := e.OrgID
	if org == "" {
		org = DefaultOrgID
	}
	now := l.now().UTC()
	id, err := store.NewUUIDv7(now, l.random)
	if err != nil {
		return fmt.Errorf("журнал технического состояния: %w", err)
	}
	var class *string
	if e.Class != "" {
		c := string(e.Class)
		class = &c
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tech_log (id, org_id, ts, component, kind, level, class, message, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::json)`,
		string(id), org, now, e.Component, string(e.Kind), string(e.Level), class, e.Message, string(details)); err != nil {
		return fmt.Errorf("журнал технического состояния: вставка: %w", err)
	}
	return nil
}
