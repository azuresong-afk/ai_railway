package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/notify"
)

// notifyChannelRoutes — каналы уведомлений (ТЗ 5.6, Р4; задача 3.13 этапа
// 3, ADR-0020 п. 9). Изменение и тестовая отправка — функция безопасности
// (notify_channels.manage): ослабление требует повторной проверки паролем
// или кодом (DM-40). Секреты каналов в ответах не показываются.
func notifyChannelRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/notify-channels", Permission: auth.PermNotifyChannelsRead,
			Handler: needNotify(d, d.listNotifyChannels)},
		{Method: http.MethodPost, Path: "/api/v1/notify-channels", Permission: auth.PermNotifyChannelsManage, Idempotent: true,
			MaxBody: notify.MaxChannelBody, Handler: needNotify(d, d.createNotifyChannel)},
		{Method: http.MethodGet, Path: "/api/v1/notify-channels/{id}", Permission: auth.PermNotifyChannelsRead,
			Handler: needNotify(d, d.getNotifyChannel)},
		{Method: http.MethodPut, Path: "/api/v1/notify-channels/{id}", Permission: auth.PermNotifyChannelsManage,
			MaxBody: notify.MaxChannelBody, Handler: needNotify(d, d.updateNotifyChannel)},
		{Method: http.MethodPost, Path: "/api/v1/notify-channels/{id}/test", Permission: auth.PermNotifyChannelsManage,
			Handler: needNotify(d, d.testNotifyChannel)},
		{Method: http.MethodGet, Path: "/api/v1/notify-channels/{id}/deliveries", Permission: auth.PermNotifyChannelsRead,
			Handler: needNotify(d, d.listNotifyDeliveries)},
	}
}

func needNotify(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Notify == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Каналы уведомлений не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

const channelNotFound = "Канал уведомлений не найден."

// notifyProblem переводит ошибки сервиса каналов в ответы API.
func notifyProblem(logger *slog.Logger, err error) *Problem {
	var ie *notify.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f := ""
			if m := fieldRe.FindStringSubmatch(e.Error()); m != nil {
				f = m[1]
			}
			fields = append(fields, FieldError{Field: f, Detail: e.Error()})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, notify.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, channelNotFound)
	case errors.Is(err, notify.ErrVersionConflict):
		return NewProblem(http.StatusConflict, CodeConflict, "Канал изменил другой пользователь: обновите страницу и повторите изменение.")
	case errors.Is(err, notify.ErrNameTaken):
		return NewProblem(http.StatusConflict, CodeConflict, "Канал с таким названием уже есть.")
	case errors.Is(err, notify.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Достигнут предел в 50 каналов: отключите или измените неиспользуемые.")
	case errors.Is(err, notify.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Изменение ослабляет доставку уведомлений: выполните его в консоли с вводом текущего пароля или кода.")
	case errors.Is(err, notify.ErrRateLimited):
		return NewProblem(http.StatusTooManyRequests, CodeRateLimited,
			"Тестовая отправка в канал — не чаще 5 раз в минуту. Повторите позже.")
	}
	logger.Error("уведомления: ошибка обработки запроса", "error", err)
	return errInternal()
}

// notifyBy — субъект запроса.
func notifyBy(r *http.Request) (notify.By, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return notify.By{}, false
	}
	c := p.Caller
	by := notify.By{Actor: audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}, IP: clientAddr(r)}
	if c.Token != nil {
		by.Actor = audit.Actor{Type: audit.ActorAPIToken, ID: c.Token.ID, Name: c.User.Login + " (" + c.Token.Prefix + ")"}
	}
	return by, true
}

// NotifyChannelView — канал в ответах: секретов нет, только какие заданы.
type NotifyChannelView struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Enabled     bool            `json:"enabled"`
	MinSeverity string          `json:"min_severity"`
	Settings    notify.Settings `json:"settings"`
	// SecretsSet — заданные секреты: password, url, signing_key.
	SecretsSet []string  `json:"secrets_set"`
	Version    int       `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  string    `json:"updated_by"`
}

func notifyChannelView(c notify.Channel) NotifyChannelView {
	s := c.SecretFields
	if s == nil {
		s = []string{}
	}
	return NotifyChannelView{ID: c.ID, Name: c.Name, Type: c.Type, Enabled: c.Enabled, MinSeverity: c.MinSeverity,
		Settings: c.Settings, SecretsSet: s, Version: c.Version, CreatedAt: c.CreatedAt.UTC(), CreatedBy: c.CreatedBy,
		UpdatedAt: c.UpdatedAt.UTC(), UpdatedBy: c.UpdatedBy}
}

// NotifyChannelList — каналы организации (не больше 50).
type NotifyChannelList struct {
	Items []NotifyChannelView `json:"items"`
}

func (d Deps) listNotifyChannels(w http.ResponseWriter, r *http.Request) {
	list, err := d.Notify.Channels(r.Context())
	if err != nil {
		WriteProblem(w, notifyProblem(d.Logger, err))
		return
	}
	out := NotifyChannelList{Items: make([]NotifyChannelView, 0, len(list))}
	for _, c := range list {
		out.Items = append(out.Items, notifyChannelView(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getNotifyChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, channelNotFound)
	if !ok {
		return
	}
	c, err := d.Notify.Channel(r.Context(), id)
	if err != nil {
		WriteProblem(w, notifyProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, notifyChannelView(c))
}

func (d Deps) createNotifyChannel(w http.ResponseWriter, r *http.Request) {
	by, ok := notifyBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req notify.ChannelInput
	if p := DecodeJSON(w, r, &req, notify.MaxChannelBody); p != nil {
		WriteProblem(w, p)
		return
	}
	c, err := d.Notify.CreateChannel(r.Context(), by, req)
	if err != nil {
		WriteProblem(w, notifyProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/notify-channels/"+c.ID)
	WriteJSON(w, http.StatusCreated, notifyChannelView(c))
}

type notifyChannelRequest struct {
	notify.ChannelInput
	reauthFields
}

func (d Deps) updateNotifyChannel(w http.ResponseWriter, r *http.Request) {
	by, ok := notifyBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, channelNotFound)
	if !ok {
		return
	}
	var req notifyChannelRequest
	if p := DecodeJSON(w, r, &req, notify.MaxChannelBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req.reauthFields, "notify_channel.update", notify.ErrConfirmRequired)
	c, err := d.Notify.UpdateChannel(r.Context(), by, id, req.ChannelInput)
	if err != nil {
		WriteProblem(w, notifyProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, notifyChannelView(c))
}

// NotifyDeliveryView — строка журнала доставки: без содержимого и
// секретов, ошибка — код без текста ответа получателя.
type NotifyDeliveryView struct {
	ID        string     `json:"id"`
	ChannelID string     `json:"channel_id"`
	AlertID   string     `json:"alert_id,omitempty"`
	Kind      string     `json:"kind"`
	Status    string     `json:"status"`
	Attempts  int        `json:"attempts"`
	NextAt    *time.Time `json:"next_at,omitempty"`
	Error     string     `json:"error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	SentAt    *time.Time `json:"sent_at,omitempty"`
}

func notifyDeliveryView(x notify.Delivery) NotifyDeliveryView {
	v := NotifyDeliveryView{ID: x.ID, ChannelID: x.ChannelID, AlertID: x.AlertID, Kind: x.Kind, Status: x.Status,
		Attempts: x.Attempts, Error: x.Error, CreatedAt: x.CreatedAt.UTC(), UpdatedAt: x.UpdatedAt.UTC(), SentAt: optTime(x.SentAt)}
	if x.Status == notify.StatusPending {
		v.NextAt = optTime(x.NextAt)
	}
	return v
}

func (d Deps) testNotifyChannel(w http.ResponseWriter, r *http.Request) {
	by, ok := notifyBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, channelNotFound)
	if !ok {
		return
	}
	x, err := d.Notify.TestChannel(r.Context(), by, id)
	if err != nil {
		WriteProblem(w, notifyProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, notifyDeliveryView(x))
}

// NotifyDeliveryList — последние строки журнала доставки канала.
type NotifyDeliveryList struct {
	Items []NotifyDeliveryView `json:"items"`
}

func (d Deps) listNotifyDeliveries(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, channelNotFound)
	if !ok {
		return
	}
	limit := 50
	if vs, ok := r.URL.Query()["limit"]; ok {
		n, err := strconv.Atoi(vs[0])
		if len(vs) != 1 || err != nil || n < 1 || n > notify.MaxDeliveriesPage {
			WriteProblem(w, Invalid("Параметры выборки заданы неверно.",
				FieldError{"limit", "Число от 1 до " + strconv.Itoa(notify.MaxDeliveriesPage) + "."}))
			return
		}
		limit = n
	}
	list, err := d.Notify.Deliveries(r.Context(), id, limit)
	if err != nil {
		WriteProblem(w, notifyProblem(d.Logger, err))
		return
	}
	out := NotifyDeliveryList{Items: make([]NotifyDeliveryView, 0, len(list))}
	for _, x := range list {
		out.Items = append(out.Items, notifyDeliveryView(x))
	}
	WriteJSON(w, http.StatusOK, out)
}
