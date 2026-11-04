package redteam

import (
	"context"
	"fmt"
)

// Выдержки ответов цели endpoint в режиме masked (ADR-0031, раздел 7;
// 5В3 ревью 5.r3). Замена категорией закрывает только найденные ПДн и
// секреты, а утёкший системный промпт или внутренние данные приложения
// остались бы в БД и её дампах открытым текстом. Поэтому выдержка
// хранится только запечатанной ключом данных, как секреты и аргументы
// подтверждений: AAD — таблица, столбец, ID запуска и сценария, так что
// шифротекст другой строки не распечатывается. Ротация ключа данных
// перешифровывает выдержки (keyring.Rewrap), а вывод версии ключа
// невозможен, пока на неё ссылается хоть одна выдержка.

// Место хранения выдержки для AAD (то же — в internal/keyring/rotate.go).
const exampleTable, exampleColumn = "redteam_results", "example"

// exampleRowID — ID строки в AAD: запуск и сценарий.
func exampleRowID(runID, scenarioID string) string { return runID + "/" + scenarioID }

// sealExample запечатывает выдержку ключом данных. Сбой шифрования —
// итог без выдержки: открытым текстом она не сохраняется никогда.
func (x *execution) sealExample(ctx context.Context, scenarioID, text string) *Sealed {
	if text == "" {
		return nil
	}
	box := x.s.o.Box
	keyID, data, err := box.SealKey(ctx, []byte(text), exampleTable, exampleColumn, exampleRowID(x.run.ID, scenarioID))
	if err != nil {
		x.logger().Error("тестирование устойчивости: выдержка ответа не запечатана, итог сохраняется без неё",
			"scenario", scenarioID, "error", err)
		return nil
	}
	return &Sealed{Data: data, KeyID: keyID, Alg: box.Alg()}
}

// Examples — открытые выдержки ответов запуска по ID сценария (только
// цель endpoint в режиме masked и удавшиеся атаки). Вызывающий проверяет
// право events.content.read и пишет запись аудита (отчёт 5.33 —
// data.export с examples=true); в API запусков выдержек нет.
func (s *Service) Examples(ctx context.Context, runID string) (map[string]string, error) {
	_, res, err := s.Run(ctx, runID)
	if err != nil {
		return nil, err
	}
	return s.openExamples(ctx, res)
}

// openExamples распечатывает выдержки итогов res.
func (s *Service) openExamples(ctx context.Context, res []Result) (map[string]string, error) {
	out := map[string]string{}
	for _, r := range res {
		if r.Example == nil {
			continue
		}
		plain, err := s.o.Box.OpenContext(ctx, r.Example.KeyID, r.Example.Data, exampleTable, exampleColumn,
			exampleRowID(r.RunID, r.ScenarioID))
		if err != nil {
			return nil, fmt.Errorf("тестирование устойчивости: выдержка сценария %s не распечатана: %w", r.ScenarioID, err)
		}
		out[r.ScenarioID] = string(plain)
		clear(plain)
	}
	return out, nil
}
