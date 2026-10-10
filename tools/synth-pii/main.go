// Команда synth-pii печатает синтетические ПДн для корпусов детекторов и
// тестов: валидные контрольные суммы, но значения не могут принадлежать
// реальным лицам (internal/detect/pii, synth.go). Значения детерминированы
// номером: synth-pii -kind inn12 -from 1 -n 5. Счёт с тем же номером, что и
// БИК, проходит проверку ключа по этому БИК.
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

const kindList = "snils, inn10, inn12, ogrn, ogrnip, card, passport, phone, email, bik, account"

func main() {
	kind := flag.String("kind", "", "вид: "+kindList)
	from := flag.Uint64("from", 1, "номер первого значения")
	n := flag.Int("n", 10, "сколько значений (до 10 000)")
	flag.Parse()
	if err := run(os.Stdout, *kind, *from, *n); err != nil {
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
