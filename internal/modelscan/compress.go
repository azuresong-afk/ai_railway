package modelscan

import (
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"io"
)

// compressionName — вид сжатия по сигнатуре или пусто. joblib сжимает pickle
// одним из этих способов; gzip, zlib и bzip2 распаковываются стандартной
// библиотекой, остальные распознаются только по сигнатуре.
func compressionName(head []byte) string {
	switch {
	case hasPrefix(head, "\x1f\x8b"):
		return "gzip"
	case hasPrefix(head, "BZh") && len(head) > 3 && head[3] >= '1' && head[3] <= '9':
		return "bzip2"
	case hasPrefix(head, "\xfd7zXZ\x00"):
		return "xz"
	case hasPrefix(head, "\x04\x22\x4d\x18"):
		return "lz4"
	case hasPrefix(head, "\x28\xb5\x2f\xfd"):
		return "zstd"
	case hasPrefix(head, "ZF0x"):
		return "joblib-zlib"
	case len(head) >= 2 && head[0] == 0x78 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0:
		return "zlib"
	}
	return ""
}

func newGzip(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }

func newZlib(r io.Reader) (io.Reader, error) { return zlib.NewReader(r) }

func newBzip2(r io.Reader) io.Reader { return bzip2.NewReader(r) }
