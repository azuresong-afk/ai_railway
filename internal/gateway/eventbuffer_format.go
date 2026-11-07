package gateway

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Формат буфера событий на диске (ADR-0037, раздел 3). Все числа —
// big-endian. Разборщики ниже принимают недоверенный ввод: каталог
// состояния мог быть изменён; покрыты FuzzEventBuffer.

// Имена в каталоге буфера.
const (
	// EventBufferDir — подкаталог буфера в каталоге состояния шлюза.
	EventBufferDir = "event-buffer"
	evbCursorFile  = "cursor"
	evbSegPrefix   = "seg-"
	evbSegSuffix   = ".evb"
	evbKeyPrefix   = "key-"
	evbKeySuffix   = ".pem"
)

// Пределы и размеры формата.
const (
	evbSegMagic    = "AISECEVB"
	evbCursorMagic = "AISECEVC"
	evbVersion     = 1
	// evbSegHeaderSize — magic (8), версия (2), флаги (2), ID ключа (8),
	// номер сегмента (8), время создания (8).
	evbSegHeaderSize = 36
	// evbRecHeaderSize — длина шифротекста (4), версия записи (1), время
	// записи (8), CRC-32C (4).
	evbRecHeaderSize = 17
	// evbCursorSize — magic (8), версия (2), сегмент (8), смещение (8),
	// записей до смещения (8), CRC-32C (4).
	evbCursorSize = 38
	// evbAEADOverhead — запас на nonce и тег AEAD сверх открытого текста.
	evbAEADOverhead = 64
	// evbMaxSealed — предел шифротекста записи: событие не больше
	// events.MaxBatchBytes (больше сервер всё равно не примет).
	evbMaxSealed = events.MaxBatchBytes + evbAEADOverhead
	// EventBufferSegmentBytes — размер, после которого сегмент закрывается.
	EventBufferSegmentBytes = 16 << 20
	// evbMaxSegment — предел файла сегмента: закрытый размер и одна запись.
	evbMaxSegment = EventBufferSegmentBytes + evbRecHeaderSize + evbMaxSealed
	// evbKeyIDSize — длина ID ключа.
	evbKeyIDSize = 8
	// evbAADPrefix — начало присоединённых данных записи.
	evbAADPrefix = "aisec-event-buffer/1"
)

var evbCRC = crc32.MakeTable(crc32.Castagnoli)

// errEVBFormat — запись, сегмент или курсор не разобраны. Подробности в
// журнал не идут: в них могут быть байты из файла.
var errEVBFormat = errors.New("буфер событий: неверный формат")

// errEVBRecordCRC — заголовок записи разобран, CRC не сошлась: потеряна
// одна запись, следующая — через h.n байт.
var errEVBRecordCRC = errors.New("буфер событий: CRC записи не сошлась")

type evbKeyID [evbKeyIDSize]byte

func (k evbKeyID) String() string { return hex.EncodeToString(k[:]) }

// evbSegHeader — заголовок сегмента.
type evbSegHeader struct {
	key     evbKeyID
	seq     uint64
	created time.Time
}

func (h evbSegHeader) encode() []byte {
	b := make([]byte, evbSegHeaderSize)
	copy(b, evbSegMagic)
	binary.BigEndian.PutUint16(b[8:], evbVersion)
	copy(b[12:20], h.key[:])
	binary.BigEndian.PutUint64(b[20:], h.seq)
	binary.BigEndian.PutUint64(b[28:], uint64(h.created.UnixNano())) //nolint:gosec // G115: время после 1970 года, обратное преобразование в parseSegHeader
	return b
}

// parseSegHeader разбирает заголовок сегмента: ровно evbSegHeaderSize байт,
// известные magic и версия, флаги нулевые.
func parseSegHeader(b []byte) (evbSegHeader, error) {
	if len(b) != evbSegHeaderSize || string(b[:8]) != evbSegMagic || binary.BigEndian.Uint16(b[8:]) != evbVersion ||
		binary.BigEndian.Uint16(b[10:]) != 0 {
		return evbSegHeader{}, errEVBFormat
	}
	var h evbSegHeader
	copy(h.key[:], b[12:20])
	h.seq = binary.BigEndian.Uint64(b[20:])
	h.created = unixNanoTime(binary.BigEndian.Uint64(b[28:]))
	return h, nil
}

func unixNanoTime(v uint64) time.Time {
	if v > 1<<62 {
		// Не время записи шлюза: дальше 2116 года.
		return time.Time{}
	}
	return time.Unix(0, int64(v)).UTC() //nolint:gosec // G115: v ≤ 2^62
}

// evbRecHeader — заголовок записи.
type evbRecHeader struct {
	n   int // длина шифротекста
	at  time.Time
	crc uint32
}

// parseRecHeader разбирает заголовок записи: известная версия, длина
// шифротекста от 1 до evbMaxSealed, время задано.
func parseRecHeader(b []byte) (evbRecHeader, error) {
	if len(b) != evbRecHeaderSize || b[4] != evbVersion {
		return evbRecHeader{}, errEVBFormat
	}
	n := binary.BigEndian.Uint32(b)
	at := unixNanoTime(binary.BigEndian.Uint64(b[5:]))
	if n == 0 || n > evbMaxSealed || at.IsZero() {
		return evbRecHeader{}, errEVBFormat
	}
	return evbRecHeader{n: int(n), at: at, crc: binary.BigEndian.Uint32(b[13:])}, nil
}

// recordCRC — CRC-32C длины, версии, времени и шифротекста.
func recordCRC(head, sealed []byte) uint32 {
	c := crc32.Update(0, evbCRC, head[:13])
	return crc32.Update(c, evbCRC, sealed)
}

// encodeRecord собирает запись из шифротекста.
func encodeRecord(at time.Time, sealed []byte) []byte {
	b := make([]byte, evbRecHeaderSize, evbRecHeaderSize+len(sealed))
	binary.BigEndian.PutUint32(b, uint32(len(sealed))) //nolint:gosec // G115: len(sealed) ≤ evbMaxSealed, проверено до вызова
	b[4] = evbVersion
	binary.BigEndian.PutUint64(b[5:], uint64(at.UnixNano())) //nolint:gosec // G115: время после 1970 года
	binary.BigEndian.PutUint32(b[13:], recordCRC(b, sealed))
	return append(b, sealed...)
}

// recordAAD — присоединённые данные записи: привязка к ключу, сегменту,
// смещению и времени записи (ADR-0037, раздел 3).
func recordAAD(key evbKeyID, seq uint64, off int64, at time.Time) []byte {
	b := make([]byte, 0, len(evbAADPrefix)+1+evbKeyIDSize+24)
	b = append(b, evbAADPrefix...)
	b = append(b, evbVersion)
	b = append(b, key[:]...)
	b = binary.BigEndian.AppendUint64(b, seq)
	b = binary.BigEndian.AppendUint64(b, uint64(off))              //nolint:gosec // G115: смещение в сегменте неотрицательно
	return binary.BigEndian.AppendUint64(b, uint64(at.UnixNano())) //nolint:gosec // G115: время после 1970 года
}

// evbCursor — следующая запись досылки: сегмент, смещение и сколько
// записей сегмента до него.
type evbCursor struct {
	seq uint64
	off int64
	idx int64
}

// before — курсор c раньше d.
func (c evbCursor) before(d evbCursor) bool {
	return c.seq < d.seq || (c.seq == d.seq && c.off < d.off)
}

func (c evbCursor) encode() []byte {
	b := make([]byte, evbCursorSize)
	copy(b, evbCursorMagic)
	binary.BigEndian.PutUint16(b[8:], evbVersion)
	binary.BigEndian.PutUint64(b[10:], c.seq)
	binary.BigEndian.PutUint64(b[18:], uint64(c.off)) //nolint:gosec // G115: смещение неотрицательно
	binary.BigEndian.PutUint64(b[26:], uint64(c.idx)) //nolint:gosec // G115: число записей неотрицательно
	binary.BigEndian.PutUint32(b[34:], crc32.Checksum(b[:34], evbCRC))
	return b
}

// parseCursor разбирает файл курсора: ровно evbCursorSize байт, magic,
// версия, CRC; смещение — не раньше заголовка и не дальше предела
// сегмента, записей не больше, чем помещается до смещения.
func parseCursor(b []byte) (evbCursor, error) {
	if len(b) != evbCursorSize || string(b[:8]) != evbCursorMagic || binary.BigEndian.Uint16(b[8:]) != evbVersion ||
		binary.BigEndian.Uint32(b[34:]) != crc32.Checksum(b[:34], evbCRC) {
		return evbCursor{}, errEVBFormat
	}
	off, idx := binary.BigEndian.Uint64(b[18:]), binary.BigEndian.Uint64(b[26:])
	if off < evbSegHeaderSize || off > evbMaxSegment || idx > (off-evbSegHeaderSize)/(evbRecHeaderSize+1) {
		return evbCursor{}, errEVBFormat
	}
	return evbCursor{seq: binary.BigEndian.Uint64(b[10:]), off: int64(off), idx: int64(idx)}, nil //nolint:gosec // G115: off ≤ evbMaxSegment
}

// segName — имя файла сегмента.
func segName(seq uint64) string { return fmt.Sprintf("%s%016x%s", evbSegPrefix, seq, evbSegSuffix) }

// keyName — имя файла ключа.
func keyName(id evbKeyID) string { return evbKeyPrefix + id.String() + evbKeySuffix }

// parseHexName разбирает имя «префикс + 16 строчных hex + суффикс».
func parseHexName(name, prefix, suffix string) (uint64, bool) {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	h := name[len(prefix) : len(name)-len(suffix)]
	if len(h) != 16 || strings.ToLower(h) != h {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 16, 64)
	return v, err == nil
}

// evbScan — итог обхода сегмента по заголовкам записей (без расшифрования).
type evbScan struct {
	header evbSegHeader
	// end — конец последней разобранной записи; records — их число.
	end     int64
	records int64
	// oldest и newest — время первой и последней записи.
	oldest, newest time.Time
	// broken — после end есть неразборчивые байты (оборванная запись или
	// подмена).
	broken bool
}

// scanSegment обходит сегмент размером size: заголовок и заголовки записей.
// Длина каждой записи проверяется до чтения тела; запись, выходящая за
// конец файла, — оборванный хвост. Неверный заголовок сегмента — ошибка.
func scanSegment(r io.ReaderAt, size int64) (evbScan, error) {
	var s evbScan
	if size < evbSegHeaderSize || size > evbMaxSegment {
		return s, errEVBFormat
	}
	hb := make([]byte, evbSegHeaderSize)
	if _, err := r.ReadAt(hb, 0); err != nil {
		return s, errEVBFormat
	}
	h, err := parseSegHeader(hb)
	if err != nil {
		return s, err
	}
	s.header, s.end = h, evbSegHeaderSize
	rb := make([]byte, evbRecHeaderSize)
	for s.end < size {
		if size-s.end < evbRecHeaderSize {
			s.broken = true
			break
		}
		if _, err := r.ReadAt(rb, s.end); err != nil {
			s.broken = true
			break
		}
		rh, err := parseRecHeader(rb)
		if err != nil || int64(rh.n) > size-s.end-evbRecHeaderSize {
			s.broken = true
			break
		}
		if s.records == 0 {
			s.oldest = rh.at
		}
		s.newest = rh.at
		s.records++
		s.end += evbRecHeaderSize + int64(rh.n)
	}
	return s, nil
}

// readRecord читает запись со смещения off сегмента длиной end: заголовок,
// шифротекст и CRC. errEVBRecordCRC — запись повреждена, но заголовок
// разобран (возвращается); другая ошибка — запись и хвост неразборчивы.
func readRecord(r io.ReaderAt, off, end int64) (evbRecHeader, []byte, error) {
	if off < evbSegHeaderSize || end-off < evbRecHeaderSize {
		return evbRecHeader{}, nil, errEVBFormat
	}
	hb := make([]byte, evbRecHeaderSize)
	if _, err := r.ReadAt(hb, off); err != nil {
		return evbRecHeader{}, nil, errEVBFormat
	}
	h, err := parseRecHeader(hb)
	if err != nil || int64(h.n) > end-off-evbRecHeaderSize {
		return evbRecHeader{}, nil, errEVBFormat
	}
	sealed := make([]byte, h.n)
	if _, err := r.ReadAt(sealed, off+evbRecHeaderSize); err != nil {
		return evbRecHeader{}, nil, errEVBFormat
	}
	if recordCRC(hb, sealed) != h.crc {
		// Заголовок разобран и в пределах: вызывающий может перешагнуть
		// запись по h.n (длины цепочки проверены обходом сегмента).
		return h, nil, errEVBRecordCRC
	}
	return h, sealed, nil
}
