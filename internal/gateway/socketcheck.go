package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// checkPeerSocket — путь ведёт к сокету (не к ссылке), у остальных нет прав на
// сокет, каталог сокета — каталог, недоступный остальным на запись, а
// владелец сокета — владелец каталога (ADR-0024, раздел 2; 4Н27 ревью
// 4.r3). Иначе сокет мог бы подменить процесс другого пользователя, и
// шлюз отправлял бы ему содержимое запросов. Подмена процессом с UID владельца
// каталога — принятый риск до этапа 5 (ADR-0024, дополнение 30.10.2026).
// Общая для клиентов aisec-ml и aisec-media (ADR-0032, раздел 2): name —
// имя процесса в тексте ошибки.
func checkPeerSocket(path, name string) error {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 {
		return errors.New(name + ": каталог сокета — не каталог или доступен на запись группе или остальным")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Type() != fs.ModeSocket {
		return errors.New(name + ": на месте сокета не сокет")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("%s: права сокета %#o: у остальных не должно быть доступа", name, info.Mode().Perm())
	}
	if du, ok := fileOwner(dir); ok {
		if su, ok := fileOwner(info); ok && su != du {
			return fmt.Errorf("%s: владелец сокета (UID %d) — не владелец каталога сокета (UID %d)", name, su, du)
		}
	}
	return nil
}
