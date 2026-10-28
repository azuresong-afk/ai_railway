// Команда aisec-server — сервер управления: API, веб-консоль, оповещения, инциденты, отчёты, аудит.
// Сейчас (задачи 2.6–2.10, 2.14, 2.15, 2.17 этапа 2): HTTPS, маршрутизатор с
// проверкой прав, Problem Details, ограничение частоты, вход в консоль,
// второй фактор, учётные записи и роли, токены API, регистрация шлюзов и внутренний API на
// отдельном порту с mTLS, приём событий шлюзов, контроль целостности.
// Статика веб-консоли встроена в бинарник (web/embed.go, ADR-0011) и
// сверяется с манифестом; раздача — в задачах каркаса консоли;
// остальные ресурсы API добавляются следующими задачами.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"
	// База часовых поясов IANA в бинарнике: первичная настройка принимает
	// пояс и на хосте без /usr/share/zoneinfo (Н43 ревью 2.r4).
	_ "time/tzdata"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/approvals"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	"github.com/azuresong-afk/ai_railway/internal/compliance"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/integrity/selftest"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/license"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/quotalease"
	"github.com/azuresong-afk/ai_railway/internal/reports"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
	"github.com/azuresong-afk/ai_railway/web"
)

var version = "dev"

// Пулы соединений с PostgreSQL. Чтение событий консолью (список, карточка,
// выгрузка, агрегаты) — в отдельном пуле с пределом времени запроса, чтобы
// медленные выборки не занимали соединения входа, журнала аудита и приёма
// событий шлюзов (В11 ревью 2.r3a).
const (
	// dbPoolSize — основной пул.
	dbPoolSize = 10
	// eventsReadPoolSize — пул чтения событий; больше api.MaxExportsTotal,
	// чтобы списки не ждали выгрузок.
	eventsReadPoolSize = 4
	// eventsReadStatementTimeout — statement_timeout пула чтения: выгрузка
	// (events.ExportTimeout) и запас.
	eventsReadStatementTimeout = events.ExportTimeout + 10*time.Second
	// dashReadPoolSize — свой пул чтения агрегатов дашбордов по пределу
	// одновременных вычислений снимков: тяжёлые дашборды за год не занимают
	// соединения поиска и выгрузки событий (3В28 ревью 3.r3).
	dashReadPoolSize = api.MaxDashComputes
	// dashReadStatementTimeout — statement_timeout пула дашбордов: срок
	// снимка (15 с) и запас; раньше обрывает контекст.
	dashReadStatementTimeout = 20 * time.Second
	// auditReadPoolSize — пул выборок журнала аудита консолью, по пределу
	// api.MaxAuditReadsTotal (В17 ревью 2.r3b).
	auditReadPoolSize = api.MaxAuditReadsTotal
	// auditReadStatementTimeout — statement_timeout пула выборок журнала:
	// срок выборки (audit.QueryTimeout) и запас; раньше обрывает контекст.
	auditReadStatementTimeout = audit.QueryTimeout + 2*time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "aisec-server", "version", version)
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("неверная конфигурация", "error", err)
		os.Exit(2)
	}
	ctx, stop := shutdownContext()
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("остановка с ошибкой", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *serverConfig, logger *slog.Logger) error {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	// Самотест до приёма запросов (ТЗ, ОЦЛ.4): криптопрофиль и встроенные
	// детекторы — сервер выполняет их в песочнице политик (2.12), по её итогам
	// политики принимаются (Н33 ревью 2.r4). Провал криптопрофиля
	// останавливает запуск всегда (ОЦЛ.5); провал детекторов — оповещение:
	// песочница не основная функция сервера, итог — в selftest.result.
	selftestRes, err := selftest.Startup(ctx, selftest.StartupConfig{
		Config: selftest.Config{Component: "server", Provider: p, Detectors: builtin.All()},
		Action: integrity.ActionAlert, Logger: logger,
	})
	if err != nil {
		return err
	}
	tp, err := p.TLS()
	if err != nil {
		return err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return err
	}
	certPEM, err := aisecCrypto.ReadPEMFile(cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("сертификат сервера: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("ключ сервера: %w", err)
	}
	db, err := store.Open(ctx, cfg.DatabaseURL, dbPoolSize)
	if err != nil {
		return err
	}
	defer db.Close()

	// Контрольные точки архивации (ADR-0008): без них после архивации
	// начало хранимой цепочки не подтверждается. Подписи точек проверяются
	// открытым ключом аудита; без ключа сервер запускается, только пока
	// точек нет (новая установка).
	var auditVerifier aisecCrypto.Verifier
	var auditPubPEM []byte
	if cfg.AuditSigningPub != "" {
		if auditPubPEM, err = aisecCrypto.ReadPEMFile(cfg.AuditSigningPub); err != nil {
			return fmt.Errorf("ключ проверки аудита: %w", err)
		}
		if auditVerifier, err = aisecCrypto.ParseVerifierPEM(p, cfg.AuditSigningPub, auditPubPEM, aisecCrypto.KeyKindAuditSigningPublic); err != nil {
			return fmt.Errorf("ключ проверки аудита: %w", err)
		}
	}
	// Ключ псевдонимов пользователей (ADR-0027, п. 6) — тот же файл, что у
	// шлюзов: логин из журнала прокси и из событий дают один псевдоним.
	var userHMACKey []byte
	var userMAC aisecCrypto.MAC
	if cfg.UserHMACKey != "" {
		if userHMACKey, err = aisecCrypto.ReadKeyFile(cfg.UserHMACKey); err != nil {
			return fmt.Errorf("ключ псевдонимов пользователей: %w", err)
		}
		if userMAC, err = p.NewMAC(userHMACKey); err != nil {
			return fmt.Errorf("ключ псевдонимов пользователей: %w", err)
		}
	}
	checkpoints, err := audit.NewPGCheckpoints(db.Pool(), p, auditVerifier)
	if err != nil {
		return err
	}
	if err := requireAuditKey(ctx, checkpoints, auditVerifier != nil, logger); err != nil {
		return err
	}
	auditReadDB, err := store.Open(ctx, cfg.DatabaseURL, auditReadPoolSize, store.WithStatementTimeout(auditReadStatementTimeout))
	if err != nil {
		return err
	}
	defer auditReadDB.Close()
	auditLog, err := audit.New(db.Pool(), p, audit.WithCheckpoints(checkpoints), audit.WithReadDB(auditReadDB.Pool()))
	if err != nil {
		return err
	}
	// Итог самотеста — в журнал аудита (selftest.result); до открытия БД
	// он есть только в техническом журнале.
	if err := selftest.RecordAudit(ctx, auditLog, selftestRes); err != nil {
		logger.Error("итог самотестирования не сохранён в журнал аудита", "class", "db", "error", err)
	}
	users, err := auth.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	// Ключ данных обязателен: без него не расшифровать секреты TOTP, а
	// роли с обязательным вторым фактором не смогли бы войти (ИАФ.5).
	box, err := keyring.Load(ctx, db.Pool(), p, cfg.KeysDir, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	// После ротации ключа данных (aisec-cli keys rotate-data) сервер
	// переходит на новую версию без перезапуска (ADR-0018, п. 3.2).
	go box.Watch(ctx, keyring.WatchInterval, func(err error) {
		logger.Warn("опрос действующей версии ключа данных не выполнен", "class", "db", "error", err)
	})
	// Проверка цепочки журнала аудита (РСБ.4, DM-43): сразу и раз в
	// -audit-verify-interval. Голова цепочки защищена имитовставкой на ключе
	// из ключа данных (вне БД). Нарушение не останавливает сервер — оно
	// поднимает уведомление в «Состоянии системы».
	// Тот же Verifier проверяет цепочку по команде из API (задача 2.4a):
	// проверки не идут параллельно, опора в памяти общая.
	chainVerifier, err := startAuditVerify(ctx, cfg, auditLog, box, logger)
	if err != nil {
		return err
	}
	roles, err := auth.NewPGRoles(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	tokens, err := auth.NewPGAPITokens(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	authOpts := []auth.Option{auth.WithSecretBox(box), auth.WithRoleStore(roles), auth.WithAPITokenStore(tokens)}
	// Вход через внешний IdP (ADR-0025): в профиле без проверки JWT
	// (gost, пока нет реализации) недоступен, локальный вход работает.
	switch idp, err := oidc.New(p); {
	case err == nil:
		authOpts = append(authOpts, auth.WithOIDC(users, idp))
	case errors.Is(err, aisecCrypto.ErrNotImplemented):
		logger.Warn("вход через внешний IdP недоступен в криптопрофиле")
	default:
		return err
	}
	// Вход через каталог LDAP (ADR-0025, 2): без TLS в профиле недоступен.
	switch dir, err := ldap.New(p); {
	case err == nil:
		authOpts = append(authOpts, auth.WithLDAP(users, dir))
	case errors.Is(err, aisecCrypto.ErrNotImplemented):
		logger.Warn("вход через каталог LDAP недоступен в криптопрофиле")
	default:
		return err
	}
	authSvc, err := auth.NewService(ctx, users, auditLog, p, authOpts...)
	if err != nil {
		return err
	}
	// Контроль целостности при запуске, раз в Interval и по команде (ОЦЛ.2).
	// Нарушение с реакцией stop после запуска останавливает сервер штатно:
	// контекст отменяется с причиной integrity.ErrViolation.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// Цепочка доверия от якоря bundle-signing.pub (ADR-0018, п. 4): ключ
	// подписи пакетов и корни УЦ после ротаций.
	trust, err := loadServerTrust(ctx, p, db, cfg.KeysDir)
	if err != nil {
		return err
	}
	integritySvc, err := startIntegrity(ctx, cfg, p, db, auditLog, logger, cancel, auditPubPEM, userHMACKey, trust)
	if err != nil {
		return err
	}

	// Реестр шлюзов и внутренний УЦ (ИАФ.10, Р8): без -ca-cert
	// регистрация отвечает 503, а внутренний порт не открывается.
	var gateways *gwregistry.Service
	var ca *serverCA
	if cfg.CACert != "" {
		if ca, err = loadServerCA(cfg, p, trust); err != nil {
			return err
		}
		gwStore, err := gwregistry.NewPGStore(db.Pool(), auditLog)
		if err != nil {
			return err
		}
		if gateways, err = gwregistry.New(gwregistry.Options{
			Store: gwStore, Provider: p, CA: ca.ca, Audit: auditLog, Logger: logger, AnchorRoot: ca.anchorRoot,
		}); err != nil {
			return err
		}
		gateways.SetRoots(ca.roots)
	} else {
		logger.Warn("внутренний УЦ не задан (-ca-cert, -ca-key): регистрация шлюзов и внутренний API выключены")
	}

	// События шлюзов (ТЗ 5.5, задача 2.15): секции создаются до приёма,
	// дальше фоновое задание раз в час держит их на неделю вперёд и удаляет
	// просроченные.
	rnd, err := p.Random()
	if err != nil {
		return err
	}
	readDB, err := store.Open(ctx, cfg.DatabaseURL, eventsReadPoolSize, store.WithStatementTimeout(eventsReadStatementTimeout))
	if err != nil {
		return err
	}
	defer readDB.Close()
	// Оповещения (ТЗ 5.6, задача 3.10, ADR-0020): правила «порог» и «новое»
	// считаются в транзакции приёма событий; встроенные правила создаются
	// при запуске. Инциденты по правилам с признаком «инцидент» (DM-08,
	// задача 3.16) создаются в той же транзакции.
	alertStore, err := alerting.NewPGStore(db.Pool(), auditLog, rnd, audit.DefaultOrgID, logger)
	if err != nil {
		return err
	}
	incidentStore, err := incidents.NewPGStore(db.Pool(), auditLog, alertStore, rnd)
	if err != nil {
		return err
	}
	// Агрегаты дашбордов (задача 3.19) прибавляются в той же транзакции приёма.
	dashDB, err := store.Open(ctx, cfg.DatabaseURL, dashReadPoolSize, store.WithStatementTimeout(dashReadStatementTimeout))
	if err != nil {
		return err
	}
	defer dashDB.Close()
	dashStore, err := events.NewDashStore(db.Pool(), dashDB.Pool(), audit.DefaultOrgID, logger)
	if err != nil {
		return err
	}
	if err := dashStore.Init(ctx); err != nil {
		return err
	}
	// Отчёты читают агрегаты через пул чтения событий: отчёт за год не
	// занимает соединения дашбордов, которых ровно по пределу вычислений
	// снимков (3В28 ревью 3.r3).
	reportsDash, err := events.NewDashStore(db.Pool(), readDB.Pool(), audit.DefaultOrgID, logger)
	if err != nil {
		return err
	}
	eventStore, err := events.NewPGStore(db.Pool(), box, auditLog, audit.DefaultOrgID, events.WithRandom(rnd),
		events.WithReadDB(readDB.Pool()),
		events.WithIngestHook(events.ChainHooks(alertStore.WithIncidents(incidentStore), dashStore.Hook())))
	if err != nil {
		return err
	}
	activeUser := func(ctx context.Context, id string) error {
		u, err := authSvc.User(ctx, id)
		if err != nil {
			return err
		}
		if u.Status != auth.StatusActive {
			return errors.New("учётная запись не активна")
		}
		return nil
	}
	alertsSvc, err := alerting.New(alerting.Options{Store: alertStore, Provider: p, OrgID: audit.DefaultOrgID,
		UserCheck: activeUser,
		RoleCheck: func(ctx context.Context, id string) error {
			_, err := authSvc.RoleDef(ctx, auth.Role(id))
			return err
		},
		Retention: alertStore})
	if err != nil {
		return err
	}
	incidentsSvc, err := incidents.New(incidents.Options{Store: incidentStore, Provider: p, Alerts: alertsSvc,
		OrgID: audit.DefaultOrgID, UserCheck: func(ctx context.Context, id string) error {
			// Ответственный — действующий пользователь, который видит инциденты.
			u, err := authSvc.User(ctx, id)
			if errors.Is(err, auth.ErrNotFound) {
				return incidents.ErrUserInactive
			}
			if err != nil {
				return err
			}
			g, err := authSvc.Grants(ctx, u.Role)
			if err != nil {
				return err
			}
			if u.Status != auth.StatusActive || !g.Allows(auth.PermIncidentsRead) {
				return incidents.ErrUserInactive
			}
			return nil
		},
		Retention: incidentStore})
	if err != nil {
		return err
	}
	if n, err := alertsSvc.EnsureBuiltins(ctx); err != nil {
		return fmt.Errorf("встроенные правила оповещений: %w", err)
	} else if n > 0 {
		logger.Info("созданы встроенные правила оповещений", "count", n)
	}
	// Каналы уведомлений (задача 3.13, Р4): адреса задаёт администратор,
	// очередь доставки — в БД. Каждое новое оповещение ставится в очередь
	// той же транзакцией, что его создаёт (задача 3.14): ошибка очереди
	// откатывает и создание оповещения вместе с приёмом событий или записью
	// аудита. Очередь подключается раньше правил аудита, чтобы ни одно
	// оповещение раздела 7 не создалось без доставки.
	notifyStore, err := notify.NewPGStore(db.Pool(), auditLog, rnd, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	alertStore.SetEnqueue(notifyStore.EnqueueAlertTx)
	// Системные правила и правила безопасности (задача 3.11, ADR-0020, п. 1)
	// считаются в транзакции записи аудита — после создания встроенных
	// правил; закрытые оповещения удаляются по сроку хранения.
	auditLog.SetRecordHook(alertStore.OnAudit)
	go alerting.RunRetention(ctx, alertStore, alerting.RetentionInterval, logger)
	go incidents.RunRetention(ctx, incidentStore, audit.DefaultOrgID, incidents.RetentionInterval, logger)
	notifyTransport, err := notify.NewTransport(p, version, notify.DefaultSendTimeout)
	if err != nil {
		return err
	}
	notifyTransport.AllowNetworks(cfg.NotifyAllowedNetworks)
	notifySvc, err := notify.New(notify.Options{Store: notifyStore, Box: box, Provider: p, Transport: notifyTransport,
		OrgID: audit.DefaultOrgID})
	if err != nil {
		return err
	}
	go notifySvc.RunDispatcher(ctx, notify.DispatchInterval, logger)
	// Передача журнала аудита в SIEM (РСБ.6, задача 3.14) каналами с подпиской.
	go notifySvc.RunAuditStream(ctx, notify.StreamInterval, logger)
	if err := events.Maintain(ctx, eventStore, logger); err != nil {
		return fmt.Errorf("секции событий: %w", err)
	}
	go events.RunMaintenance(ctx, eventStore, events.MaintainEvery, logger)
	// Агрегаты для дашбордов (задача 2.16) — фоновым заданием раз в минуту.
	go events.RunAggregates(ctx, eventStore, events.AggregateEvery, logger)
	go dashStore.RunBackfill(ctx, events.DashBackfillEvery)

	// Распределённые квоты (задача 4.29, ADR-0021): аренда квот и жёстких
	// бюджетов шлюзам на внутреннем порту, режим — в консоли; выдачи старше
	// двух окон удаляются раз в минуту.
	quotaStore, err := quotalease.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	quotaSvc, err := quotalease.New(quotalease.Options{Store: quotaStore, IDs: ids.NewGenerator(rnd), OrgID: audit.DefaultOrgID,
		Logger: logger.With("component", "quota_lease")})
	if err != nil {
		return err
	}
	go quotaSvc.RunCleanup(ctx, quotalease.CleanupInterval)

	// «Состояние системы» (задача 2.20): шлюзы читаются из реестра и без
	// внутреннего УЦ; уведомления ВРМ.1, РСБ.5, ОЦЛ.5 пишутся в аудит при
	// смене состояния, раз в минуту.
	var bundleSvc atomic.Pointer[build.Service]
	timezone := func(ctx context.Context) (string, error) {
		st, err := authSvc.InstallSettings(ctx)
		return st.Timezone, err
	}
	// Срок действующего корня УЦ — условие ca_expiry (3В5 ревью 3.r1).
	var caNotAfter time.Time
	if ca != nil {
		caNotAfter = ca.ca.NotAfter()
	}
	// Приём журналов по syslog (задача 4.23) — раздел «Состояния системы»;
	// сервис теневого ИИ создаётся ниже.
	var shadowRef atomic.Pointer[shadowai.Service]
	shadowSyslog := func() shadowai.SyslogStats {
		if s := shadowRef.Load(); s != nil {
			return s.SyslogStats()
		}
		return shadowai.SyslogStats{}
	}
	// Лицензия (ТЗ 5.15, задачи 4.26–4.27, ADR-0026): подпись сохранённой
	// лицензии проверяется заново при запуске и раз в минуту, отметка часов
	// поднимается тогда же; предел шлюзов — в транзакции регистрации.
	licStore, err := license.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	licSvc, err := license.New(license.Options{Store: licStore, Provider: p, OrgID: audit.DefaultOrgID,
		Logger: logger.With("component", "license"),
		Usage:  func(ctx context.Context) (license.Usage, error) { return licStore.Usage(ctx, audit.DefaultOrgID) }})
	if err != nil {
		return err
	}
	go licSvc.Run(ctx, license.RefreshInterval)
	if gateways != nil {
		gateways.SetAdmission(licSvc.CheckGateway)
	}
	statusSvc, err := newStatus(ctx, cfg, db, auditLog, integritySvc, selftestRes, bundleHealth(&bundleSvc), timezone, caNotAfter,
		licSvc.State, quotaHealth(quotaSvc), shadowSyslog, logger)
	if err != nil {
		return err
	}

	// Политики и их версии (ТЗ 5.3, задача 2.12): проверяются строго по
	// встроенным детекторам и детекторам уровня сессии — тем же, что у шлюза.
	detectors, err := detect.NewRegistry(builtin.Catalog()...)
	if err != nil {
		return err
	}
	policyStore, err := versions.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	policiesSvc, err := versions.New(versions.Options{Store: policyStore, Provider: p, Catalog: detectors})
	if err != nil {
		return err
	}

	// Приложения, ключи и провайдеры (ТЗ 5.4, задача 2.11): учётные данные
	// провайдеров — под ключом данных (ЗИ.1); владелец приложения —
	// действующая учётная запись консоли.
	appStore, err := apps.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	appsSvc, err := apps.New(apps.Options{Store: appStore, Provider: p, Box: box, Policies: policiesSvc,
		OwnerCheck: activeUser})
	if err != nil {
		return err
	}
	// Смена политики приложения на более слабую требует подтверждения (В23 ревью 2.r5).
	appsSvc.SetPolicyWeaker(policiesSvc.Weaker)
	appsSvc.SetDefaultStorage(func(ctx context.Context) (string, error) {
		st, err := authSvc.InstallSettings(ctx)
		return st.RetentionMode, err
	})
	// Месяц расхода и бюджетов — в часовом поясе установки; счётчики
	// расхода приходят от шлюзов в heartbeat (задача 3.18).
	appsSvc.SetTimezone(func(ctx context.Context) (string, error) {
		st, err := authSvc.InstallSettings(ctx)
		return st.Timezone, err
	})
	if gateways != nil {
		gateways.SetBudgetSync(appsSvc)
	}
	// Агенты, MCP-серверы и инструменты (ТЗ 5.10, задача 4.8): учётные
	// данные MCP-серверов — под ключом данных (ЗИ.1); оповещения
	// agents.tool_new и agents.tool_changed (DM-25) — по записям аудита.
	agentStore, err := agents.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	agentsSvc, err := agents.New(agents.Options{Store: agentStore, Provider: p, Box: box, Apps: agents.AppsOf(appsSvc),
		OrgID: audit.DefaultOrgID})
	if err != nil {
		return err
	}
	// Очередь подтверждений вызовов инструментов (DM-22, задача 4.10):
	// аргументы — под ключом данных (ЗИ.1), удаляются через 30 суток после
	// закрытия, запросы — по сроку метаданных событий.
	approvalStore, err := approvals.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	approvalsSvc, err := approvals.New(approvals.Options{Store: approvalStore, Provider: p, Box: box, OrgID: audit.DefaultOrgID,
		MetadataDays: func(ctx context.Context) (int, error) {
			r, err := eventStore.Retention(ctx)
			return r.MetadataDays, err
		}, Logger: logger.With("component", "approvals")})
	if err != nil {
		return err
	}
	go approvalsSvc.Run(ctx, approvals.RunInterval)
	// Правила «частота», «аномалия» и «бюджет» (задача 3.12, Р3) — фоновой
	// задачей раз в минуту; расход — приложений с заданным бюджетом.
	alertStore.SetBudgetSource(budgetUsage(appsSvc))
	go alerting.RunPeriodic(ctx, alertStore, alerting.PeriodicInterval, logger)

	// Соответствие требованиям (ТЗ 5.18, задача 4.24): база требований —
	// встроенная и подписанная загруженная (ADR-0027); снимок настроек
	// собирается из сервисов сервера, содержимое запросов не читается.
	complianceStore, err := compliance.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	complianceSvc, err := compliance.New(compliance.Options{Store: complianceStore, Provider: p, OrgID: audit.DefaultOrgID,
		Facts: &compliance.SystemFacts{Apps: appsSvc, Policies: policiesSvc, Roles: authSvc, Status: statusSvc, Alerts: alertsSvc,
			Channels: notifySvc, Detectors: detectors, Logger: logger.With("component", "compliance")},
		Logger: logger.With("component", "compliance")})
	if err != nil {
		return err
	}
	if err := complianceSvc.Load(ctx); err != nil {
		logger.Error("соответствие: загруженная база не прочитана из БД", "class", "db", "error", err)
	}

	// Отчёты (ТЗ 5.8, S10; задача 3.24) строятся из агрегатов дашбордов,
	// инцидентов, оповещений и бюджетов; рассылка по расписанию (задача
	// 3.25) идёт через почтовый канал уведомлений. Время расписаний — в
	// часовом поясе установки.
	reportStore, err := reports.NewPGStore(db.Pool(), auditLog, audit.DefaultOrgID)
	if err != nil {
		return err
	}
	reportsSvc, err := reports.New(reports.Options{
		Store: reportStore,
		Builder: &reports.Builder{Dash: reportsDash, Incidents: incidentsSvc, Alerts: alertsSvc, Compliance: complianceSvc,
			Facts: &reports.PGFacts{DB: readDB.Pool(), OrgID: audit.DefaultOrgID, Apps: appsSvc, Policies: policiesSvc, Gateways: gateways}},
		Mailer: notifySvc, Channels: notifySvc, Directory: api.ReportDirectory{Auth: authSvc},
		Location: func(ctx context.Context) (*time.Location, error) {
			tz, err := timezone(ctx)
			if err != nil {
				return nil, err
			}
			return time.LoadLocation(tz)
		},
		IDs: ids.NewGenerator(rnd), OrgID: audit.DefaultOrgID, Logger: logger,
	})
	if err != nil {
		return err
	}
	go reportsSvc.Run(ctx, reports.TickInterval)

	// Теневой ИИ (ТЗ 5.11, DM-37; задача 4.22, ADR-0027): каталог —
	// подписанная служебная база, подпись сохранённого файла проверяется
	// заново при запуске; сводки старше срока удаляются раз в час.
	shadowStore, err := shadowai.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return err
	}
	shadowSvc, err := shadowai.New(shadowai.Options{Store: shadowStore, Provider: p, OrgID: audit.DefaultOrgID, UserMAC: userMAC,
		Location: func(ctx context.Context) (*time.Location, error) {
			tz, err := timezone(ctx)
			if err != nil {
				return nil, err
			}
			return time.LoadLocation(tz)
		},
		IDs: ids.NewGenerator(rnd), Logger: logger.With("component", "shadow_ai")})
	if err != nil {
		return err
	}
	if err := shadowSvc.Load(ctx); err != nil {
		logger.Error("теневой ИИ: каталог не прочитан из БД", "class", "db", "error", err)
	}
	go shadowSvc.RunRetention(ctx, shadowai.RetentionInterval)
	shadowRef.Store(shadowSvc)
	// Приём журналов прокси по syslog (задача 4.23): выключен по умолчанию;
	// при остановке сервера накопленные сводки записываются.
	// Выход из run по любой ошибке после запуска тоже ждёт последней
	// записи сводок (4.23-6).
	syslogCtx, stopSyslog := context.WithCancel(ctx)
	// Без модуля лицензии shadow_ai строки по syslog не учитываются, как
	// импорт файлом получает 403 license_module (4В18 ревью 4.r2).
	shadowLicensed := func(ctx context.Context) (bool, error) {
		err := licSvc.CheckModule(ctx, license.ModuleShadowAI)
		var d *license.Denied
		if errors.As(err, &d) {
			return false, nil
		}
		return err == nil, err
	}
	syslogDone, err := startShadowSyslog(syslogCtx, cfg.ShadowAISyslog, tp, shadowSvc, shadowLicensed, auditLog,
		logger.With("component", "shadow_ai"))
	if err != nil {
		stopSyslog()
		return err
	}
	defer func() {
		stopSyslog()
		if syslogDone != nil {
			<-syslogDone
		}
	}()

	// Консоль отдаётся, только если она собрана (make web-build перед go build); иначе сервер — чистый API.
	var console http.Handler
	if dist, err := fs.Sub(web.Dist, "dist"); err == nil {
		if c, err := consoleFS(dist); err == nil {
			console = staticFallback(c)
		} else {
			logger.Warn("веб-консоль не встроена: выполните make web-build до сборки сервера", "component", "aisec-server", "version", version)
		}
	}

	handler, _, err := api.New(api.Options{
		Logger: logger, Version: version, Hasher: hasher,
		Apps:       appsSvc,
		Policies:   policiesSvc,
		Ready:      db.Ping,
		Auth:       authSvc,
		Gateways:   gateways,
		Integrity:  integritySvc,
		Status:     statusSvc,
		Events:     eventStore,
		Alerts:     alertsSvc,
		Notify:     notifySvc,
		Agents:     agentsSvc,
		Approvals:  approvalsSvc,
		ShadowAI:   shadowSvc,
		Compliance: complianceSvc,
		License:    licSvc,
		Quotas:     quotaSvc,
		Incidents:  incidentsSvc,
		Dashboards: dashStore,
		Reports:    reportsSvc,
		Audit:      auditLog,
		Fallback:   console,

		AuditLog:      auditLog,
		AuditVerifier: chainVerifier,

		TrustedProxies: cfg.TrustedProxies,
		// Потоки SSE дашбордов закрываются в начале остановки (3Н44).
		Stopping: ctx.Done(),
	})
	if err != nil {
		return err
	}
	srv, err := httpserver.New(ctx, httpserver.Config{
		Addr: cfg.Listen, Handler: handler, TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM, Logger: logger,
	})
	if err != nil {
		return err
	}
	servers := []*httpserver.Server{srv}
	if gateways != nil {
		// Пакеты конфигурации (задача 2.13): без ключа подписи внутренний
		// порт не открывается — шлюзы не получили бы конфигурацию.
		bundleRoutes, bsvc, err := newBundleRoutes(cfg, p, db, auditLog, appsSvc, policiesSvc, agentsSvc, gateways, trust, authSvc.IdPKeys,
			quotaSvc.Mode, logger)
		if err != nil {
			return err
		}
		bundleRoutes = append(bundleRoutes, api.AgentsInternalRoutes(agentsSvc, logger.With("listener", "internal"))...)
		bundleRoutes = append(bundleRoutes, api.ApprovalsInternalRoutes(approvalsSvc, logger.With("listener", "internal"))...)
		bundleRoutes = append(bundleRoutes, api.QuotaInternalRoutes(quotaSvc, logger.With("listener", "internal"))...)
		bundleSvc.Store(bsvc)
		internal, err := newInternalServer(ctx, cfg, tp, hasher, gateways, eventStore, approvalsSvc, quotaSvc, ca, certPEM, keyPEM,
			bundleRoutes, logger)
		if err != nil {
			return err
		}
		servers = append(servers, internal)
	}
	recordStart(ctx, auditLog, logger)
	logger.Info("сервер управления запущен")
	err = runAll(ctx, servers...)
	// Сводки syslog записываются до записи об остановке сервера.
	stopSyslog()
	if syslogDone != nil {
		<-syslogDone
		syslogDone = nil
	}
	if cause := context.Cause(ctx); errors.Is(cause, integrity.ErrViolation) {
		err = errors.Join(err, cause)
	}
	recordStop(ctx, auditLog, err, logger)
	return err
}

// quotaHealth — режим квот и шлюзы на автономной доле для «Состояния
// системы» (задача 4.29).
func quotaHealth(svc *quotalease.Service) func(context.Context) (sysstatus.QuotaHealth, error) {
	return func(ctx context.Context) (sysstatus.QuotaHealth, error) {
		h, err := svc.Health(ctx)
		return sysstatus.QuotaHealth{Mode: h.Mode, Autonomous: h.Autonomous}, err
	}
}

// budgetUsage — расход приложений с бюджетом за текущий месяц для правил
// «бюджет» (задача 3.12).
func budgetUsage(svc *apps.Service) alerting.BudgetSource {
	return func(ctx context.Context) ([]alerting.BudgetUsage, error) {
		st, _, err := svc.BudgetStatuses(ctx, "")
		if err != nil {
			return nil, err
		}
		var out []alerting.BudgetUsage
		for i := range st {
			if st[i].Budget == nil {
				continue
			}
			out = append(out, alerting.BudgetUsage{AppID: st[i].App.ID, App: st[i].App.Slug, Month: st[i].Month,
				Mode: st[i].Budget.Mode, Percent: st[i].Percent, Exhausted: st[i].Exhausted})
		}
		return out, nil
	}
}

// newStatus собирает «Состояние системы» и запускает фоновую проверку
// условий уведомлений раздела 7.
func newStatus(ctx context.Context, cfg *serverConfig, db *store.DB, auditLog *audit.Log, integritySvc integrity.Service,
	selftestRes selftest.Result, bundle func(context.Context) (*sysstatus.BundleHealth, error),
	timezone func(context.Context) (string, error), caNotAfter time.Time, lic func(context.Context) (license.State, error),
	quota func(context.Context) (sysstatus.QuotaHealth, error), shadowSyslog func() shadowai.SyslogStats,
	logger *slog.Logger) (*sysstatus.Service, error) {
	gwStore, err := gwregistry.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return nil, err
	}
	pg, err := sysstatus.NewPGStore(db.Pool(), auditLog, audit.DefaultOrgID)
	if err != nil {
		return nil, err
	}
	// Сертификат заказчика для адреса шлюза — условие customer_cert_expiry
	// (задача 3.27): читаются только имя адреса и срок, ключ не открывается.
	appStore, err := apps.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return nil, err
	}
	customerCert := func(ctx context.Context) (sysstatus.CustomerCert, bool, error) {
		t, err := appStore.GatewayTLS(ctx, audit.DefaultOrgID)
		switch {
		case errors.Is(err, apps.ErrNoGatewayTLS):
			return sysstatus.CustomerCert{}, false, nil
		case err != nil:
			return sysstatus.CustomerCert{}, false, err
		}
		return sysstatus.CustomerCert{Host: t.Host, NotAfter: t.Cert.NotAfter, Fingerprint: t.Cert.Fingerprint}, true, nil
	}
	failed := len(selftestRes.Failures)
	if !selftestRes.CryptoOK {
		failed++
	}
	svc, err := sysstatus.New(sysstatus.Options{
		Version: version, StartedAt: time.Now(),
		Selftest:  &sysstatus.SelftestSummary{OK: selftestRes.OK(), At: selftestRes.At, Failed: failed},
		Gateways:  sysstatus.GatewayLister{Store: gwStore},
		Integrity: integritySvc.Store, Store: pg,
		Timezone: timezone, StorageLimit: cfg.AuditStorageLimit, WarnPercent: cfg.AuditStorageWarnPercent,
		Logger: logger, Bundle: bundle, CANotAfter: caNotAfter, CustomerCert: customerCert, License: lic, Quota: quota,
		ShadowAISyslog: shadowSyslog,
	})
	if err != nil {
		return nil, err
	}
	go svc.Run(ctx, sysstatus.DefaultEvalInterval)
	return svc, nil
}

// checkpointSource — наличие контрольных точек архивации (audit.PGCheckpoints).
type checkpointSource interface {
	Any(ctx context.Context) (bool, error)
}

// requireAuditKey не даёт запуститься без открытого ключа аудита, если в
// журнале уже есть контрольные точки: иначе точку с любой подписью приняли
// бы за настоящую (решение владельца по В5 ревью 2.r1).
func requireAuditKey(ctx context.Context, cps checkpointSource, haveKey bool, logger *slog.Logger) error {
	if haveKey {
		return nil
	}
	exist, err := cps.Any(ctx)
	if err != nil {
		return err
	}
	if exist {
		return errors.New("в журнале аудита есть контрольные точки архивации, а ключ их проверки не задан: " +
			"укажите -audit-signing-pub (audit-signing.pub из aisec-cli init)")
	}
	logger.Warn("ключ проверки контрольных точек аудита не задан (-audit-signing-pub): после первой архивации сервер без него не запустится")
	return nil
}

// startAuditVerify запускает фоновую проверку цепочки журнала аудита и
// возвращает её Verifier для проверки по команде.
func startAuditVerify(ctx context.Context, cfg *serverConfig, auditLog *audit.Log, box *keyring.Box, logger *slog.Logger) (*audit.Verifier, error) {
	// Опоры прежних версий ключа данных сверяются, пока версия не удалена
	// ротацией (ADR-0018, п. 3.4). Версии берутся из box перед каждой
	// проверкой: после keys rotate-data опора пишется новой версией без
	// перезапуска (3В2 ревью 3.r1).
	opts, err := audit.HeadMACOptions(box)
	if err != nil {
		return nil, err
	}
	v := audit.NewVerifier(auditLog, opts...)
	go func() {
		// Итог каждой проверки уже в аудите и audit_verifications; здесь —
		// только техническое сообщение.
		err := v.Run(ctx, cfg.AuditVerifyInterval, func(res audit.Verification, verr error) {
			switch {
			case verr != nil && ctx.Err() == nil:
				logger.Error("проверка цепочки журнала аудита не выполнена", "class", "db", "error", verr)
			case verr == nil && !res.OK():
				logger.Error("цепочка журнала аудита нарушена", "class", "integrity",
					"broken_seq", res.Break.Seq, "reason", string(res.Break.Reason))
			}
		})
		if err != nil {
			logger.Error("проверка цепочки журнала аудита не запущена", "error", err)
		}
	}()
	return v, nil
}

// startIntegrity проверяет целостность сервера при запуске и запускает
// периодическую проверку. Сверяются исполняемый файл, встроенная статика
// веб-консоли и корни доверия (В19 ревью 2.r4): ключ проверки аудита
// (auditPubPEM — прочитанные при запуске байты), сертификат УЦ и открытые
// ключи подписи пакетов. Сертификаты TLS не наблюдаются: их меняют при
// продлении.
func startIntegrity(ctx context.Context, cfg *serverConfig, p aisecCrypto.Provider, db *store.DB, auditLog *audit.Log,
	logger *slog.Logger, stop context.CancelCauseFunc, auditPubPEM, userHMACKey []byte, trust *serverTrust) (integrity.Service, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = "" // проверка отметит исполняемый файл как нечитаемый
	}
	manifest := cfg.Manifest
	if manifest == "" {
		manifest = integrity.DefaultManifestPath(exe)
	}
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return integrity.Service{}, err
	}
	var watch []integrity.WatchFile
	if cfg.AuditSigningPub != "" {
		watch = append(watch, integrity.WatchFile{Path: cfg.AuditSigningPub, Data: auditPubPEM})
	}
	if cfg.CACert != "" {
		watch = append(watch, integrity.WatchFile{Path: cfg.CACert})
	}
	if cfg.UserHMACKey != "" {
		watch = append(watch, integrity.WatchFile{Path: cfg.UserHMACKey, Data: userHMACKey})
	}
	if trust != nil {
		watch = append(watch, trust.watch(cfg)...)
	}
	running := ""
	if exe != "" {
		running = integrity.RunningExecutable(exe)
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "server", Provider: p, ManifestPath: manifest,
		Executable: running, BinaryName: "bin/aisec-server",
		Embedded: map[string]fs.FS{"web/dist": dist}, Watch: watch,
	})
	if err != nil {
		return integrity.Service{}, err
	}
	pg, err := integrity.NewPGStore(db.Pool(), auditLog, p)
	if err != nil {
		return integrity.Service{}, err
	}
	mon, err := integrity.NewMonitor(integrity.MonitorConfig{
		Checker: checker, Action: cfg.IntegrityAction, Interval: cfg.IntegrityInterval, Logger: logger,
		Record: pg.Record, OnStop: stop,
	})
	if err != nil {
		return integrity.Service{}, err
	}
	if _, err := mon.Startup(ctx); err != nil {
		return integrity.Service{}, err
	}
	go mon.Run(ctx)
	return integrity.Service{Monitor: mon, Store: pg}, nil
}

// loadCA читает внутренний УЦ: сертификат и ключ (права 0400 или 0600).
func loadCA(certFile, keyFile string) (*aisecCrypto.CA, error) {
	certPEM, err := aisecCrypto.ReadPEMFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("сертификат УЦ: %w", err)
	}
	keyPEM, err := aisecCrypto.ReadKeyFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("ключ УЦ: %w", err)
	}
	ca, err := aisecCrypto.LoadCA(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("внутренний УЦ: %w", err)
	}
	return ca, nil
}

// newInternalServer — внутренний API шлюзов на отдельном порту: TLS с
// обязательным клиентским сертификатом внутреннего УЦ (mTLS, ИАФ.10).
func newInternalServer(ctx context.Context, cfg *serverConfig, tp aisecCrypto.TLSProvider, hasher aisecCrypto.Hasher,
	gateways *gwregistry.Service, eventStore events.Store, approvalsSvc *approvals.Service, quotaSvc *quotalease.Service,
	ca *serverCA, certPEM, keyPEM []byte,
	extra []api.Route, logger *slog.Logger) (*httpserver.Server, error) {
	if cfg.InternalTLSCertFile != "" {
		var err error
		if certPEM, err = aisecCrypto.ReadPEMFile(cfg.InternalTLSCertFile); err != nil {
			return nil, fmt.Errorf("сертификат внутреннего порта: %w", err)
		}
		if keyPEM, err = aisecCrypto.ReadKeyFile(cfg.InternalTLSKeyFile); err != nil {
			return nil, fmt.Errorf("ключ внутреннего порта: %w", err)
		}
	}
	ilog := logger.With("listener", "internal")
	handler, _, err := api.NewInternal(api.InternalOptions{Logger: ilog, Hasher: hasher, Gateways: gateways, Events: eventStore,
		Approvals: approvalsSvc, Quotas: quotaSvc, Extra: extra})
	if err != nil {
		return nil, err
	}
	return httpserver.New(ctx, httpserver.Config{
		Addr: cfg.InternalListen, Handler: handler, TLS: tp, CertPEM: certPEM, KeyPEM: keyPEM,
		ClientCAPEM: ca.clientCAs, Logger: ilog,
	})
}

// runAll обслуживает все порты; ошибка одного останавливает остальные.
func runAll(ctx context.Context, servers ...*httpserver.Server) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errs <- s.Run(ctx) }()
	}
	var all []error
	for range servers {
		if err := <-errs; err != nil {
			all = append(all, err)
			cancel()
		}
	}
	return errors.Join(all...)
}
