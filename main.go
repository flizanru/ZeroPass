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
	flag.StringVar(&path, "vault", "", "путь к файлу хранилища (по умолчанию — LocalAppData\\ZeroPass)")
	flag.Parse()

	if path == "" {
		p, err := vault.DefaultPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "не удалось определить каталог exe:", err)
			os.Exit(1)
		}
		path = p
	}

	go func() {
		err := gui.Run(path)
		memguard.Purge()
		if clipErr := secure.WaitForClipboardClear(); clipErr != nil {
			fmt.Fprintln(os.Stderr, "ZeroPass: не удалось очистить буфер обмена перед выходом:", clipErr)
			if err == nil {
				err = clipErr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "ZeroPass:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}
