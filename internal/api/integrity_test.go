package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// fakeIntegrity — контроль целостности без файлов и БД.
type fakeIntegrity struct {
	latest []integrity.Result
	by     []audit.Actor
	ip     []netip.Addr
	res    integrity.Result
	err    error
}

func (f *fakeIntegrity) Latest(context.Context) ([]integrity.Result, error) { return f.latest, f.err }

func (f *fakeIntegrity) CheckBy(_ context.Context, by audit.Actor, ip netip.Addr) (integrity.Result, error) {
	f.by, f.ip = append(f.by, by), append(f.ip, ip)
	return f.res, f.err
}

func TestIntegrityLatest(t *testing.T) {
	at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	fi := &fakeIntegrity{latest: []integrity.Result{{Component: "server", Trigger: integrity.TriggerStartup, At: at,
		Reason: integrity.ReasonFilesMismatch, ManifestVersion: "1.0", TestSigned: true, Checked: 2,
		Failures: []integrity.Failure{{Path: "web/dist/index.html", Problem: integrity.ProblemModified}}}}}
	h, _ := newHandler(t, Options{Integrity: fi, Authorizer: allowPerm{auth.PermSystemRead: true}})
	w := do(h, http.MethodGet, "/api/v1/system/integrity", "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got IntegrityList
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].OK || got.Items[0].Reason != "files_mismatch" || !got.Items[0].TestSigned ||
		got.Items[0].Failures[0].Path != "web/dist/index.html" || !got.Items[0].CheckedAt.Equal(at) {
		t.Fatalf("%+v", got)
	}
}

func TestIntegrityVerifyByUser(t *testing.T) {
	fi := &fakeIntegrity{res: integrity.Result{Component: "server", Trigger: integrity.TriggerManual, Reason: integrity.ReasonOK, Checked: 3}}
	h, _ := newHandler(t, Options{Integrity: fi, Authorizer: allowPerm{PermIntegrityVerify: true}})
	w := do(h, http.MethodPost, "/api/v1/system/integrity/verify", "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got IntegrityCheck
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !got.OK || got.CheckedFiles != 3 || got.Failures == nil {
		t.Fatalf("%+v %v", got, err)
	}
	// В аудит проверка идёт от имени пользователя консоли и с его адресом (РСБ.1).
	if len(fi.by) != 1 || fi.by[0].Type != audit.ActorUser || fi.by[0].Name != "u1" || fi.ip[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("%+v %+v", fi.by, fi.ip)
	}
}

// Отказ в доступе: проверка по команде требует права integrity.verify.
// До задачи 2.9 его нет ни у одной роли — сессия любой роли получает 403,
// а без сессии — 401.
func TestIntegrityVerifyDenied(t *testing.T) {
	fi := &fakeIntegrity{}
	h, _ := newHandler(t, Options{Integrity: fi, Authorizer: allowPerm{auth.PermSystemRead: true}})
	mustProblem(t, do(h, http.MethodPost, "/api/v1/system/integrity/verify", ""), http.StatusForbidden, CodeForbidden)
	h, _ = newHandler(t, Options{Integrity: fi, Authorizer: DenyAll{}})
	mustProblem(t, do(h, http.MethodPost, "/api/v1/system/integrity/verify", ""), http.StatusUnauthorized, CodeUnauthorized)
	mustProblem(t, do(h, http.MethodGet, "/api/v1/system/integrity", ""), http.StatusUnauthorized, CodeUnauthorized)
	h, _ = newHandler(t, Options{Integrity: fi, Authorizer: allowPerm{}})
	mustProblem(t, do(h, http.MethodGet, "/api/v1/system/integrity", ""), http.StatusForbidden, CodeForbidden)
	if len(fi.by) != 0 {
		t.Fatal("проверка выполнена без права")
	}
	for _, role := range []auth.Role{auth.RoleSecurityAdmin, auth.RoleSystemAdmin, auth.RoleAnalyst, auth.RoleAuditor, auth.RoleAppOwner} {
		c := auth.Caller{User: auth.User{Role: role}, Session: auth.Session{State: auth.SessionActive}}
		if auth.Allowed(c, PermIntegrityVerify) {
			t.Errorf("роль %s получила %s до модели ролей 2.9", role, PermIntegrityVerify)
		}
	}
}

func TestIntegrityUnavailable(t *testing.T) {
	h, _ := newHandler(t, Options{Auth: testAuth(t, authtest.NewMemory()), Authorizer: allowPerm{auth.PermSystemRead: true, PermIntegrityVerify: true}})
	mustProblem(t, do(h, http.MethodGet, "/api/v1/system/integrity", ""), http.StatusServiceUnavailable, CodeUnavailable)
	fi := &fakeIntegrity{err: integrity.ErrInterrupted}
	h, _ = newHandler(t, Options{Integrity: fi, Authorizer: allowPerm{auth.PermSystemRead: true, PermIntegrityVerify: true}})
	mustProblem(t, do(h, http.MethodPost, "/api/v1/system/integrity/verify", ""), http.StatusServiceUnavailable, CodeUnavailable)
	fi.err = errTest
	w := do(h, http.MethodGet, "/api/v1/system/integrity", "")
	mustProblem(t, w, http.StatusInternalServerError, CodeInternal)
}
