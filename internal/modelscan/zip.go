package modelscan

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// ZIP читается только по центральному каталогу (archive/zip): локальные
// заголовки и данные вне записей каталога не используются. Число записей и
// размер каталога проверяются своим разбором конца каталога до archive/zip,
// чтобы огромный каталог не был прочитан в память целиком.

const (
	eocdLen       = 22
	eocd64LocLen  = 20
	eocd64Len     = 56
	maxZipComment = 0xffff
	// zipPeek — сколько байт начала каждой записи распаковывается для
	// поиска pickle по сигнатуре.
	zipPeek = 4096
	// maxZipNames — имён записей с pickle в пояснении.
	maxZipNames = 5
)

// zipDirectory — сведения из конца центрального каталога.
type zipDirectory struct {
	entries uint64
	size    uint64
	offset  uint64
}

// readZipDirectory находит запись конца центрального каталога (и её вариант
// ZIP64) и возвращает число записей, размер и смещение каталога.
func readZipDirectory(r io.ReaderAt, size int64) (zipDirectory, error) {
	if size < eocdLen {
		return zipDirectory{}, errors.New("файл короче записи конца каталога ZIP")
	}
	tailLen := min(size, eocdLen+maxZipComment)
	tail := make([]byte, tailLen)
	if _, err := r.ReadAt(tail, size-tailLen); err != nil && !errors.Is(err, io.EOF) {
		return zipDirectory{}, err
	}
	pos := -1
	for i := len(tail) - eocdLen; i >= 0; i-- {
		if string(tail[i:i+4]) == "PK\x05\x06" && i+eocdLen+int(le16(tail[i+20:])) == len(tail) {
			pos = i
			break
		}
	}
	if pos < 0 {
		return zipDirectory{}, errors.New("нет записи конца центрального каталога ZIP")
	}
	e := tail[pos:]
	d := zipDirectory{entries: uint64(le16(e[10:])), size: uint64(le32(e[12:])), offset: uint64(le32(e[16:]))}
	eocdAt := size - tailLen + int64(pos)
	if d.entries == 0xffff || d.size == 0xffffffff || d.offset == 0xffffffff {
		if eocdAt < eocd64LocLen {
			return zipDirectory{}, errors.New("нет указателя ZIP64")
		}
		var loc [eocd64LocLen]byte
		if _, err := r.ReadAt(loc[:], eocdAt-eocd64LocLen); err != nil {
			return zipDirectory{}, err
		}
		if string(loc[:4]) == "PK\x06\x07" {
			at := le64(loc[8:])
			if at > uint64(size) || uint64(size)-at < eocd64Len {
				return zipDirectory{}, errors.New("запись ZIP64 за концом файла")
			}
			var rec [eocd64Len]byte
			if _, err := r.ReadAt(rec[:], int64(at)); err != nil {
				return zipDirectory{}, err
			}
			if string(rec[:4]) != "PK\x06\x06" {
				return zipDirectory{}, errors.New("нет записи конца каталога ZIP64")
			}
			d = zipDirectory{entries: le64(rec[32:]), size: le64(rec[40:]), offset: le64(rec[48:])}
		}
	}
	if d.offset > uint64(size) || d.size > uint64(size)-d.offset {
		return zipDirectory{}, errors.New("центральный каталог ZIP за концом файла")
	}
	return d, nil
}

// scanZip — архив ZIP: архив PyTorch (*/data.pkl), .npz (записи .npy),
// прочий ZIP. Каждая запись проверяется по сигнатуре на pickle.
func (s *Scanner) scanZip(r io.ReaderAt, size int64, fr *FileReport) {
	dir, err := readZipDirectory(r, size)
	if err != nil {
		fr.add(CodeMalformed, SeverityBlock, "ZIP: %v", err)
		return
	}
	if dir.entries > s.limits.MaxZipEntries {
		fr.add(CodeLimitExceeded, SeverityBlock, "ZIP: записей в каталоге %d, предел %d", dir.entries, s.limits.MaxZipEntries)
		return
	}
	if dir.size > s.limits.MaxZipDirectory {
		fr.add(CodeLimitExceeded, SeverityBlock, "ZIP: центральный каталог %d байт, предел %d", dir.size, s.limits.MaxZipDirectory)
		return
	}
	zr, err := zip.NewReader(r, size)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		fr.add(CodeMalformed, SeverityBlock, "ZIP: %v", err)
		return
	}
	if uint64(len(zr.File)) > s.limits.MaxZipEntries {
		fr.add(CodeLimitExceeded, SeverityBlock, "ZIP: записей %d, предел %d", len(zr.File), s.limits.MaxZipEntries)
		return
	}
	var pickles []string
	var pickleWalkInfo pickleWalk
	npy, files, unread := 0, 0, 0
	torch := false
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		files++
		base := path.Base(f.Name)
		if base == "data.pkl" && strings.Contains(f.Name, "/") {
			torch = true
		}
		rc, err := f.Open()
		if err != nil {
			unread++
			continue
		}
		if strings.HasSuffix(strings.ToLower(base), ".npy") {
			npy++
			s.scanNumpy(rc, int64(min(f.UncompressedSize64, 1<<62)), fr, f.Name) //nolint:gosec // G115: размер ограничен 2^62
			_ = rc.Close()
			continue
		}
		head := make([]byte, zipPeek)
		n, _ := io.ReadFull(rc, head)
		_ = rc.Close()
		head = head[:n]
		isPickle := strings.HasSuffix(strings.ToLower(base), ".pkl") ||
			n >= 2 && head[0] == opProto && head[1] <= 5 || looksLikePickle(head)
		if isPickle {
			if len(pickles) == 0 {
				pickleWalkInfo, _ = walkPickle(head)
			}
			if len(pickles) < maxZipNames {
				pickles = append(pickles, clean(f.Name))
			}
		}
	}
	switch {
	case torch:
		fr.Format = FormatPyTorch
	case npy > 0 && npy == files:
		fr.Format = FormatNumpyZip
	}
	if len(pickles) > 0 {
		what := "архив ZIP с pickle"
		if torch {
			what = "архив PyTorch (ZIP с data.pkl)"
		}
		fr.add(CodePickle, SeverityBlock, "%s", pickleDetail(fmt.Sprintf("%s: %s", what, strings.Join(pickles, ", ")), pickleWalkInfo))
	} else if torch {
		fr.add(CodePickle, SeverityBlock, "архив PyTorch (ZIP с data.pkl): запись не прочитана; pickle — запрет без исключений (DM-27)")
	}
	if unread > 0 {
		fr.add(CodeNotScanned, SeverityWarn, "ZIP: записей не прочитано (шифрование или неизвестное сжатие): %d", unread)
	}
}

// scanCompressed — сжатый поток (joblib, .pkl.gz и т. п.): начало
// распаковывается стандартной библиотекой и проверяется на pickle; сжатие,
// которого в ней нет, — содержимое не проверено.
func scanCompressed(head []byte, fr *FileReport) {
	name := compressionName(head)
	plain, ok := decompressHead(name, head)
	if !ok {
		fr.add(CodeUnknownFormat, SeverityWarn, "сжатый поток %s: содержимое не проверено", name)
		return
	}
	if len(plain) >= 2 && plain[0] == opProto && plain[1] <= 5 || looksLikePickle(plain) {
		w, _ := walkPickle(plain)
		fr.add(CodePickle, SeverityBlock, "%s", pickleDetail("поток pickle, сжатый "+name+" (joblib или .pkl."+name+")", w))
		return
	}
	fr.add(CodeUnknownFormat, SeverityWarn, "сжатый поток %s: содержимое не распознано", name)
}

// decompressHead распаковывает не больше zipPeek байт из начала потока.
func decompressHead(name string, head []byte) ([]byte, bool) {
	var rd io.Reader
	var err error
	switch name {
	case "gzip":
		rd, err = newGzip(bytes.NewReader(head))
	case "zlib":
		rd, err = newZlib(bytes.NewReader(head))
	case "bzip2":
		rd = newBzip2(bytes.NewReader(head))
	default:
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	out := make([]byte, zipPeek)
	n, err := io.ReadFull(rd, out)
	if n == 0 && err != nil {
		return nil, false
	}
	return out[:n], true
}
