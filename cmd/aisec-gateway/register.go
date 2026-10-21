package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
)

// Файлы, которые создаёт aisec-gateway register.
const (
	regKeyFile  = "gateway.key"
	regCertFile = "gateway.crt"
	regCAFile   = "ca.crt"
	// tokenEnv — токен регистрации; только из окружения: аргументы видны в
	// списке процессов.
	tokenEnv = "AISEC_GATEWAY_REGISTRATION_TOKEN"
)

// regConfig — параметры aisec-gateway register.
type regConfig struct {
	Console   string
	ConsoleCA string
	OutDir    string
	Token     string
}

func loadRegConfig(args []string, getenv func(string) string, errOut io.Writer) (*regConfig, error) {
	fs := flag.NewFlagSet("aisec-gateway register", flag.ContinueOnError)
	fs.SetOutput(errOut)
	console := fs.String("console", "", "адрес консоли сервера управления, https://хост:8444 (обязательный)")
	consoleCA := fs.String("console-ca", "", "корневой сертификат для проверки консоли, PEM (обязательный)")
	outDir := fs.String("out-dir", "", "существующий каталог 0700 для gateway.key, gateway.crt и ca.crt (обязательный)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	cfg := &regConfig{Console: *console, ConsoleCA: *consoleCA, OutDir: *outDir, Token: getenv(tokenEnv)}
	var errs []error
	for name, v := range map[string]string{"console": cfg.Console, "console-ca": cfg.ConsoleCA, "out-dir": cfg.OutDir, tokenEnv: cfg.Token} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s: обязательный параметр", name))
		}
	}
	if cfg.Console != "" {
		if _, err := config.ParseServerURL(cfg.Console); err != nil {
			errs = append(errs, errors.New("console: только https://хост:порт"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("регистрация шлюза: %w", err)
	}
	return cfg, nil
}

// runRegister — aisec-gateway register: ключ и CSR создаются здесь, сервер
// подписывает CSR по токену (ИАФ.10). Существующие файлы не перезаписываются:
// для новой регистрации нужен новый каталог или удаление прежних файлов.
func runRegister(ctx context.Context, cfg *regConfig, out io.Writer) error {
	root, err := os.OpenRoot(cfg.OutDir)
	if err != nil {
		return fmt.Errorf("каталог: %w", err)
	}
	defer func() { _ = root.Close() }() //nolint:gosec // G104: файлы записаны и синхронизированы раньше; закрытие каталога ничего не теряет
	info, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("каталог: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: каталог доступен группе или остальным (права %04o); нужно 0700", cfg.OutDir, info.Mode().Perm())
	}
	// До обращения к серверу: иначе токен будет погашен впустую.
	for _, name := range []string{regKeyFile, regCertFile, regCAFile} {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: файл уже существует или недоступен; прежняя регистрация не перезаписывается", name)
		}
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return fmt.Errorf("самотест: %w", err)
	}
	tp, err := p.TLS()
	if err != nil {
		return err
	}
	rootsPEM, err := aisecCrypto.ReadPEMFile(cfg.ConsoleCA)
	if err != nil {
		return fmt.Errorf("корневой сертификат консоли: %w", err)
	}
	transport, err := gateway.ControlTransport(tp, rootsPEM, nil, nil)
	if err != nil {
		return err
	}
	console, err := config.ParseServerURL(cfg.Console)
	if err != nil {
		return err
	}
	reg, err := gateway.Register(ctx, &http.Client{Transport: transport}, console, cfg.Token)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		perm fs.FileMode
	}{
		{regKeyFile, reg.KeyPEM, 0o600},
		{regCertFile, reg.CertPEM, 0o644},
		{regCAFile, reg.CAPEM, 0o644},
	} {
		if err := writeNew(root, f.name, f.data, f.perm); err != nil {
			return fmt.Errorf("%s: %w; токен уже погашен — выпустите новый: aisec-cli gateway token -name %s -reregister", f.name, err, reg.Name)
		}
	}
	if d, err := root.Open("."); err == nil {
		err = d.Sync()
		_ = d.Close() //nolint:gosec // G104: важна ошибка Sync выше; каталог открыт только для чтения
		if err != nil {
			return fmt.Errorf("каталог: %w", err)
		}
	}
	_, err = fmt.Fprintf(out, "Шлюз %s зарегистрирован (ID %s), сертификат действует до %s.\n"+
		"Запуск: aisec-gateway ... -server https://<сервер>:8445 -server-ca <корень сервера> -client-cert %s/%s -client-key %s/%s"+
		" -bundle-pub <bundle-signing.pub> -state-dir <каталог 0700>\n",
		reg.Name, reg.GatewayID, reg.NotAfter.UTC().Format("2006-01-02"), cfg.OutDir, regCertFile, cfg.OutDir, regKeyFile)
	return err
}

func writeNew(root *os.Root, name string, data []byte, perm fs.FileMode) (err error) {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
