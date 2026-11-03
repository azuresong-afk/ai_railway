package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/media"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Модели OCR (ADR-0033, задача 5.41): детектор строк и распознавание
// PaddleOCR в ONNX из набора RapidOCR v3.10.0. Файлы — в каталоге выпуска
// models/ (их хеши — и в манифесте выпуска aisec-media, его сверяет
// самопроверка), а SHA-256 каждой модели ещё и встроен сюда: модель с
// другим хешем не загружается, даже если манифест подменён вместе с ней.
// Те же хеши — в deploy/build/ocr/models.json (источники для make
// media-models) и в ML-BOM deploy/build/ocr/mlbom.cdx.json; совпадение
// проверяет TestOCRModelHashesMatchLock.

// ocrModel — модель OCR: имя файла в каталоге моделей и SHA-256.
type ocrModel struct {
	File   string
	SHA256 string
}

var (
	ocrDetModel = ocrModel{File: "PP-OCRv6_det_small.onnx", SHA256: "090f04abcd9d9a7498bc4ebf677e4cb9bdce1fe4197ddb7e529f1ef44e1ff94f"}
	ocrRecModel = ocrModel{File: "cyrillic_PP-OCRv5_rec_mobile.onnx", SHA256: "90f761b4bfcce0c8c561c0cb5c887b0971d3ec01c32164bdf7374a35b0982711"}
)

// maxOCRModel — предел размера файла модели (модели — 9,9 и 8,1 МиБ).
const maxOCRModel = 64 << 20

// loadOCRModel читает модель из каталога dir с пределом размера и сверяет
// хеш (SHA-256, криптопрофиль standard) со встроенным: сеанс ONNX Runtime
// создаётся из уже проверенных байтов, файл повторно не читается.
func loadOCRModel(dir string, m ocrModel, p aisecCrypto.Provider) ([]byte, error) {
	want, err := hex.DecodeString(m.SHA256)
	if err != nil {
		return nil, err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, m.File)) //nolint:gosec // G304: каталог задаёт администратор флагом -models, файл сверяется с встроенным хешем
	if err != nil {
		return nil, fmt.Errorf("модель OCR: %w", err)
	}
	defer f.Close() //nolint:errcheck // файл только читается
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxOCRModel {
		return nil, fmt.Errorf("модель OCR %s: не обычный файл или больше %d байт", m.File, maxOCRModel)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxOCRModel+1))
	if err != nil {
		return nil, fmt.Errorf("модель OCR %s: %w", m.File, err)
	}
	if len(data) > maxOCRModel || !aisecCrypto.Equal(hasher.Sum(data), want) {
		return nil, fmt.Errorf("модель OCR %s: хеш не совпадает со встроенным при сборке", m.File)
	}
	return data, nil
}

// parseCharset — таблица символов модели распознавания из её метаданных
// (ключ character, по символу на строку). classes — число классов выхода:
// если оно на два больше числа символов, последний класс — пробел
// (use_space_char PaddleOCR); класс 0 — пустой символ CTC.
func parseCharset(meta string, classes int64) ([]string, error) {
	chars := strings.Split(strings.TrimRight(meta, "\n"), "\n")
	if int64(len(chars))+2 == classes {
		chars = append(chars, " ")
	}
	if int64(len(chars))+1 != classes {
		return nil, fmt.Errorf("модель распознавания: классов %d, символов в метаданных %d", classes, len(chars))
	}
	return chars, nil
}

// ocrSelftestPNG — эталонное изображение самопроверки OCR: первая строка
// clean-01 корпуса testdata/corpus/media (синтетика).
//
//go:embed testdata/ocr-selftest.png
var ocrSelftestPNG []byte

// ocrSelftestText — текст эталонного изображения.
const ocrSelftestText = "Инструкция по настройке принтера"

// errOCRSelftest — самопроверка OCR не прошла.
var errOCRSelftest = errors.New("самопроверка OCR: эталонное изображение распознано неверно")

// ocrSelftest распознаёт эталонное изображение до приёма запросов: модели,
// библиотека и пред- и постобработка дают ожидаемый текст. Иначе
// aisec-media не запускается (шлюз ставит отметку «не проверено»).
func ocrSelftest(ctx context.Context, an media.Analyzer) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := an.Analyze(ctx, ocrSelftestPNG)
	if err != nil {
		return fmt.Errorf("самопроверка OCR: %w", err)
	}
	for _, t := range res.Texts {
		if t.Source == wire.SourceOCR && strings.Contains(t.Text, ocrSelftestText) {
			return nil
		}
	}
	return errOCRSelftest
}
