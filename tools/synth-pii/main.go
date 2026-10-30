// Команда synth-pii печатает синтетические ПДн для корпусов детекторов и
// тестов: валидные контрольные суммы, но значения не могут принадлежать
// реальным лицам (internal/detect/pii, synth.go). Значения детерминированы
// номером: synth-pii -kind inn12 -from 1 -n 5. Счёт с тем же номером, что и
// БИК, проходит проверку ключа по этому БИК. Вид ner — фразы с размеченными
// именами, организациями и адресами для pii.ner (ner.go): synth-pii -kind
// ner -split check -format corpus -n 260.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
)

var kinds = map[string]func(uint64) string{
	"snils": pii.SynthSNILS, "inn10": pii.SynthINN10, "inn12": pii.SynthINN12,
	"ogrn": pii.SynthOGRN, "ogrnip": pii.SynthOGRNIP, "card": pii.SynthCard,
	"passport": pii.SynthPassport, "phone": pii.SynthPhone, "email": pii.SynthEmail,
	"bik": pii.SynthBIK, "account": pii.SynthAccount,
}

const kindList = "snils, inn10, inn12, ogrn, ogrnip, card, passport, phone, email, bik, account, ner"

func main() {
	kind := flag.String("kind", "", "вид: "+kindList)
	from := flag.Uint64("from", 1, "номер первого значения")
	n := flag.Int("n", 10, "сколько значений (до 10 000)")
	split := flag.String("split", "train", "ner: часть корпуса — train (обучение) или check (проверка)")
	format := flag.String("format", "corpus", "ner: corpus — строки корпуса детекторов, spans — текст и сущности для обучения")
	flag.Parse()
	var err error
	if *kind == "ner" {
		err = runNER(os.Stdout, *split, *format, *from, *n)
	} else {
		err = run(os.Stdout, *kind, *from, *n)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "synth-pii:", err)
		os.Exit(2)
	}
}

func run(w io.Writer, kind string, from uint64, n int) error {
	gen, ok := kinds[kind]
	if !ok {
		return errors.New("неизвестный вид; допустимо: " + kindList)
	}
	if n < 1 || n > 10000 {
		return errors.New("n — от 1 до 10 000")
	}
	for i := range uint64(n) {
		if _, err := fmt.Fprintln(w, gen(from+i)); err != nil {
			return err
		}
	}
	return nil
}
