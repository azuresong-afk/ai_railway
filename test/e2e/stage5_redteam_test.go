//go:build e2e

package e2e

// Тестирование устойчивости (задачи 5.30–5.33 этапа 5, ADR-0031; DM-01 как
// строка, которую проверяют атаки): живые сервер, шлюз и mock-llm. Цель
// «gateway» — приложение продукта: сервер выпускает ключ запуска, ждёт его
// доставки шлюзу и отправляет атаки из базы сценариев через шлюз; события
// помечены test и оповещений не создают. Результаты читаются по API, итоги
// выводит aisec-cli redteam run (код 3 — доля удавшихся атак выше порога).

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// s5RunCard — запуск тестирования устойчивости.
type s5RunCard struct {
	ID        string         `json:"id"`
	Status    string         `json:"status"`
	Reason    string         `json:"reason"`
	Scenarios int            `json:"scenarios"`
	Counts    map[string]int `json:"counts"`
	Results   []struct {
		ScenarioID string   `json:"scenario_id"`
		Threat     string   `json:"threat"`
		Verdict    string   `json:"verdict"`
		EventIDs   []string `json:"event_ids"`
	} `json:"results"`
}

func TestE2EStage5_RedTeamThroughGateway(t *testing.T) {
	gwAddr := freeAddr(t)
	st := s3NewStack(t, s3Opts{serverArgsFn: func(s *s2Stand) []string {
		return []string{"-redteam-gateway-url", "https://" + gwAddr, "-redteam-gateway-ca", s.tls.ca}
	}})
	st.env.listen = gwAddr
	st.policy("support")
	app := st.app("redteam-app", "support")
	st.startGateway()
	_ = app

	// База сценариев — подписанный файл (ADR-0028); библиотека с тестовой
	// подписью. Повреждённый файл не принимается (422), целый — 200.
	lib0 := mustRead(t, "../../testdata/redteam/scenarios-library-test.aisecdb")
	broken := append([]byte{}, lib0...)
	broken[len(broken)/2] ^= 0x01
	if r := st.admin.doRaw("PUT", "/api/v1/redteam/scenarios", "application/octet-stream", broken); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("повреждённая база сценариев: %s", r)
	}
	if r := st.admin.doRaw("PUT", "/api/v1/redteam/scenarios", "application/octet-stream", lib0); r.code != http.StatusOK {
		t.Fatalf("загрузка базы сценариев: %s", r)
	}

	// База сценариев действует и содержит атаки на строку DM-01 на русском.
	r := st.admin.do("GET", "/api/v1/redteam/scenarios", nil)
	var lib struct {
		Scenarios []struct{ ID, Lang, Threat string } `json:"scenarios"`
	}
	r.json(t, &lib)
	n := 0
	for _, s := range lib.Scenarios {
		if s.Threat == "DM-01" && s.Lang == "ru" {
			n++
		}
	}
	if r.code != http.StatusOK || n == 0 {
		t.Fatalf("сценарии DM-01 (ru): %d: %s", n, r)
	}

	// Цель gateway: приложение и модель. Созданием целей управляет
	// администратор безопасности из консоли.
	r = st.admin.do("POST", "/api/v1/redteam/targets", map[string]any{"name": "Шлюз e2e", "kind": "gateway", "app_id": app.id,
		"model": "mock-echo"})
	if r.code != http.StatusCreated {
		t.Fatalf("цель тестирования: %s", r)
	}
	var target struct{ ID string }
	r.json(t, &target)

	// Запуск из консоли: DM-01 на русском. Политика «support» блокирует
	// инъекции — атаки не должны удаваться.
	r = st.admin.do("POST", "/api/v1/redteam/runs", map[string]any{"target_id": target.ID, "threats": []string{"DM-01"}, "lang": "ru"})
	if r.code != http.StatusAccepted {
		t.Fatalf("запуск: %s", r)
	}
	var run s5RunCard
	r.json(t, &run)
	waitRun := func(id string) s5RunCard {
		var card s5RunCard
		if !s2WaitFor(4*time.Minute, func() bool {
			r := st.admin.do("GET", "/api/v1/redteam/runs/"+id, nil)
			if r.code != http.StatusOK {
				t.Fatalf("запуск %s: %s", id, r)
			}
			card = s5RunCard{}
			r.json(t, &card)
			return card.Status != "running" && card.Status != "queued"
		}) {
			t.Fatalf("запуск %s не завершился: %+v", id, card)
		}
		return card
	}
	card := waitRun(run.ID)
	if card.Status != "done" || len(card.Results) != n || card.Counts["succeeded"] != 0 {
		t.Fatalf("итог запуска: %+v", card)
	}
	if card.Counts["blocked"]+card.Counts["defended"] == 0 {
		t.Fatalf("ни одна атака не отражена: %+v", card.Counts)
	}
	// События запуска помечены как тестовые и не создают оповещений о
	// настоящей атаке (DM-01).
	for _, res := range card.Results {
		if res.Threat != "DM-01" || len(res.EventIDs) == 0 {
			continue
		}
		ev := st.admin.do("GET", "/api/v1/events/"+res.EventIDs[0], nil)
		if ev.code != http.StatusOK || !strings.Contains(string(ev.body), `"test":true`) {
			t.Fatalf("событие запуска %s не помечено test: %s", res.EventIDs[0], ev)
		}
		break
	}

	// Запуск из CI: aisec-cli redteam run токеном API с правами redteam.run
	// и redteam.read. Все атаки отражены — код 0, итоги — в файле без
	// промптов и ответов цели.
	r = st.admin.do("POST", "/api/v1/api-tokens", map[string]any{"name": "ci", "password": s2AdminPass,
		"permissions": []map[string]string{{"permission": "redteam.run"}, {"permission": "redteam.read"}}})
	if r.code != http.StatusCreated {
		t.Fatalf("токен CI: %s", r)
	}
	var tok struct{ Token string }
	r.json(t, &tok)
	dir := t.TempDir()
	tokenFile, outFile := filepath.Join(dir, "ci.token"), filepath.Join(dir, "result.json")
	mustWrite(t, tokenFile, []byte(tok.Token+"\n"))
	out, code := st.s.cli("redteam", "run", "-server", st.s.base, "-ca", st.s.tls.ca, "-token-file", tokenFile, "-target", target.ID,
		"-threats", "DM-01", "-lang", "ru", "-poll", "2s", "-wait", "5m", "-threshold", "0", "-out", outFile)
	if code != 0 || strings.Contains(out, tok.Token) {
		t.Fatalf("aisec-cli redteam run: код %d\n%s", code, out)
	}
	res := string(mustRead(t, outFile))
	if !strings.Contains(res, "DM-01") || strings.Contains(res, "Ignore") {
		t.Fatalf("итоги запуска из CI: %s", res)
	}

	// Два запуска атак на инъекции не подняли оповещение «Промпт-инъекция
	// заблокирована» (DM-01): события запусков тестовые.
	if a := st.waitAlertOnce("threshold.injection_blocked"); a.ID != "" {
		t.Fatalf("тестовые атаки подняли оповещение: %+v", a)
	}

	// Права: токен без redteam.run запустить тестирование не может.
	r = st.admin.do("POST", "/api/v1/api-tokens", map[string]any{"name": "ro", "password": s2AdminPass,
		"permissions": []map[string]string{{"permission": "redteam.read"}}})
	var ro struct{ Token string }
	r.json(t, &ro)
	c := st.s.client("198.51.100.81")
	c.bearer = ro.Token
	if r := c.doOpt("POST", "/api/v1/redteam/runs", map[string]any{"target_id": target.ID}, false); r.code != http.StatusForbidden {
		t.Fatalf("запуск токеном без redteam.run: %s", r)
	}
}
