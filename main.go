package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"gioui.org/app"
	"github.com/awnumar/memguard"

	"zeropass/internal/gui"
	"zeropass/internal/secure"
	"zeropass/internal/vault"
)

func main() {
	secure.SuppressCrashDumps()
	debug.SetTraceback("none")
	memguard.CatchInterrupt()

	var path string
	var noProcessACL, strictHandles bool
	flag.StringVar(&path, "vault", "", "путь к файлу хранилища (по умолчанию — LocalAppData\\ZeroPass)")
	flag.BoolVar(&noProcessACL, "no-process-acl", false, "не ограничивать доступ к процессу (только для разработки)")
	flag.BoolVar(&strictHandles, "strict-handles", false, "включить аварийное завершение при неверных handle")
	flag.Parse()
	secure.SetStrictHandles(strictHandles)
	mitigationErrors := secure.ApplyMitigations()

	if path == "" {
		p, err := vault.DefaultPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ZeroPass: не удалось подготовить защищённый каталог хранилища")
			os.Exit(1)
		}
		path = p
	}

	go func() {
		err := gui.Run(path, noProcessACL, mitigationErrors)
		memguard.Purge()
		if clipErr := secure.WaitForClipboardClear(); clipErr != nil {
			fmt.Fprintln(os.Stderr, "ZeroPass: не удалось очистить буфер обмена перед выходом:", clipErr)
			if err == nil {
				err = clipErr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "ZeroPass: приложение завершилось с ошибкой")
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}
