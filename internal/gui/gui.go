package gui

import (
	"image"
	"image/color"
	"runtime"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/event"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/awnumar/memguard"

	"zeropass/internal/secure"
	"zeropass/internal/vault"
)

const (
	productName  = "ZeroPass"
	productTitle = "ZeroPass — защищённое хранилище"

	idleTimeout  = 5 * time.Minute
	idleTick     = time.Second
	clipboardTTL = 15 * time.Second
	pwGenLen     = 20
)

type stage int

const (
	stageUnlock stage = iota
	stageCreate
	stageRecover
	stageList
	stageDetail
	stageEdit
	stageConfirmDelete
)

type statusLevel int

const (
	statusNone statusLevel = iota
	statusOK
	statusWarn
	statusErr
)

type App struct {
	mu         sync.Mutex
	done       chan struct{}
	tickerDone chan struct{}
	hwnd       uintptr
	w          *app.Window
	th         *material.Theme
	path       string

	protected bool
	protNote  string

	stage     stage
	vault     *vault.Vault
	lastAct   time.Time
	lastFrame time.Time
	dt        float32

	status   string
	statusLv statusLevel

	pw1, pw2   *securePW
	primaryBtn widget.Clickable
	recoverBtn widget.Clickable
	busy       bool
	busyMsg    string
	authCh     chan authResult

	list    widget.List
	rows    []entryRow
	addBtn  widget.Clickable
	lockBtn widget.Clickable
	search  widget.Editor

	detailID   int64
	detailMeta vault.EntryMeta
	revealed   *memguard.LockedBuffer
	showBtn    widget.Clickable
	copyBtn    widget.Clickable
	editBtn    widget.Clickable
	delBtn     widget.Clickable
	backBtn    widget.Clickable

	form *editForm

	deleteID   int64
	deleteName string
	yesBtn     widget.Clickable
	noBtn      widget.Clickable
}

type entryRow struct {
	meta  vault.EntryMeta
	click widget.Clickable
	hover float32
}

var darkPalette = material.Palette{
	Bg:         color.NRGBA{R: 0x15, G: 0x16, B: 0x1a, A: 0xff},
	Fg:         color.NRGBA{R: 0xe8, G: 0xe8, B: 0xec, A: 0xff},
	ContrastBg: color.NRGBA{R: 0xf2, G: 0xf2, B: 0xf5, A: 0xff},
	ContrastFg: color.NRGBA{R: 0x15, G: 0x16, B: 0x1a, A: 0xff},
}

func Run(path string) error {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection()))
	th.Palette = darkPalette

	a := &App{
		th:         th,
		path:       path,
		lastAct:    time.Now(),
		pw1:        newSecurePW("мастер-пароль"),
		pw2:        newSecurePW("повторите пароль"),
		done:       make(chan struct{}),
		tickerDone: make(chan struct{}),
	}
	a.list.Axis = layout.Vertical
	a.search.SingleLine = true
	defer a.destroy()

	if err := a.initStage(); err != nil {
		return err
	}

	w := new(app.Window)
	w.Option(
		app.Title(productTitle),
		app.Size(unit.Dp(760), unit.Dp(580)),
		app.MinSize(unit.Dp(560), unit.Dp(420)),
	)
	a.w = w

	go a.idleTicker()

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.Win32ViewEvent:
			a.mu.Lock()
			a.onWindowHandle(e.HWND)
			a.mu.Unlock()
		case app.FrameEvent:
			a.mu.Lock()
			gtx := app.NewContext(&ops, e)
			a.frame(gtx)
			e.Frame(gtx.Ops)
			a.mu.Unlock()
		}
	}
}

func (a *App) idleTicker() {
	t := time.NewTicker(idleTick)
	defer t.Stop()
	defer close(a.tickerDone)
	for {
		select {
		case <-a.done:
			return
		case now := <-t.C:
			a.mu.Lock()
			a.checkSession(now)
			a.pollAuth()
			a.mu.Unlock()
			if a.w != nil {
				a.w.Invalidate()
			}
		}
	}
}

func (a *App) onWindowHandle(hwnd uintptr) {
	a.hwnd = hwnd
	if hwnd == 0 {
		return
	}
	if err := secure.ProtectHWND(hwnd); err != nil {
		a.protected = false
		a.protNote = err.Error()
	} else {
		a.protected = true
		a.protNote = ""
	}
	_ = secure.DarkTitleBar(hwnd)
}

func kdfCPUCap() func() {
	n := runtime.GOMAXPROCS(0)
	if n <= 1 {
		return func() {}
	}
	runtime.GOMAXPROCS(n - 1)
	return func() { runtime.GOMAXPROCS(n) }
}

func (a *App) act(gtx layout.Context) { a.lastAct = gtx.Now }
func (a *App) setErr(err error)       { a.status, a.statusLv = err.Error(), statusErr }
func (a *App) setOK(s string)         { a.status, a.statusLv = s, statusOK }
func (a *App) setWarn(s string)       { a.status, a.statusLv = s, statusWarn }
func (a *App) clearStatus()           { a.status, a.statusLv = "", statusNone }

func (a *App) initStage() error {
	st, err := vaultState(a.path)
	switch st {
	case vaultAbsent:
		a.stage = stageCreate
		a.pw1.focus()
	case vaultPresent:
		a.stage = stageUnlock
		a.pw1.focus()
	case vaultOnlyBackup:
		a.stage = stageRecover
	default:
		return err
	}
	return nil
}

func (a *App) frame(gtx layout.Context) {
	a.checkSession(gtx.Now)

	if !a.lastFrame.IsZero() {
		d := gtx.Now.Sub(a.lastFrame).Seconds()
		if d < 0 {
			d = 0
		} else if d > 0.05 {
			d = 0.05
		}
		a.dt = float32(d)
	}
	a.lastFrame = gtx.Now

	a.pollAuth()

	if a.busy {
		gtx.Execute(op.InvalidateCmd{})
	}

	paint.Fill(gtx.Ops, a.th.Bg)

	a.trackActivity(gtx)

	layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		switch a.stage {
		case stageCreate, stageUnlock:
			return a.layoutAuth(gtx)
		case stageRecover:
			return a.layoutRecover(gtx)
		case stageList:
			return a.layoutList(gtx)
		case stageDetail:
			return a.layoutDetail(gtx)
		case stageEdit:
			return a.layoutEdit(gtx)
		case stageConfirmDelete:
			return a.layoutConfirm(gtx)
		}
		return layout.Dimensions{}
	})
}

func (a *App) unlocked() bool {
	switch a.stage {
	case stageList, stageDetail, stageEdit, stageConfirmDelete:
		return true
	}
	return false
}

func (a *App) trackActivity(gtx layout.Context) {
	for {
		ev, ok := gtx.Event(pointer.Filter{
			Target: a,
			Kinds:  pointer.Press | pointer.Release | pointer.Move | pointer.Scroll | pointer.Drag,
		})
		if !ok {
			break
		}
		if _, isPtr := ev.(pointer.Event); isPtr {
			a.act(gtx)
		}
	}
	defer clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Push(gtx.Ops).Pop()
	event.Op(gtx.Ops, a)
}

func (a *App) lock(msg string) {
	a.destroyRevealed()
	if a.form != nil {
		a.form.destroy()
		a.form = nil
	}
	if a.vault != nil {
		a.vault.Lock()
		a.vault = nil
	}
	a.rows = nil
	a.detailID, a.detailMeta = 0, vault.EntryMeta{}
	a.deleteID, a.deleteName = 0, ""
	a.search.SetText("")
	a.pw1.clear()
	a.pw2.clear()
	a.stage = stageUnlock
	a.pw1.focus()
	if msg != "" {
		a.setWarn(msg)
	} else {
		a.clearStatus()
	}
	if err := secure.ClearClipboardIfOwned(); err != nil {
		a.setErr(err)
	}
}

func (a *App) destroyRevealed() {
	if a.revealed != nil {
		a.revealed.Destroy()
		a.revealed = nil
	}
}

func (a *App) destroy() {
	if a.done != nil {
		close(a.done)
	}
	if a.w != nil && a.tickerDone != nil {
		<-a.tickerDone
	}
	if a.authCh != nil {
		res := <-a.authCh
		if res.v != nil {
			res.v.Lock()
		}
		a.authCh = nil
	}
	a.destroyRevealed()
	if a.form != nil {
		a.form.destroy()
	}
	if a.vault != nil {
		a.vault.Lock()
	}
	if a.pw1 != nil {
		a.pw1.destroy()
	}
	if a.pw2 != nil {
		a.pw2.destroy()
	}
}

func (a *App) pollAuth() {
	if a.authCh == nil {
		return
	}
	select {
	case res := <-a.authCh:
		a.onAuthResult(res)
	default:
	}
}

func deadlineExpired(now, last time.Time) bool {
	return now.Before(last) || now.Sub(last) >= idleTimeout || now.Round(0).Sub(last.Round(0)) >= idleTimeout
}

func (a *App) checkSession(now time.Time) {
	if !a.unlocked() {
		return
	}
	if deadlineExpired(now, a.lastAct) {
		a.lock("хранилище заблокировано по тайм-ауту бездействия")
	} else if a.hwnd != 0 && secure.SessionUnavailable(a.hwnd) {
		a.lock("хранилище заблокировано при сворачивании или смене сеанса Windows")
	}
}

func (a *App) statusBar(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.status == "" {
				return layout.Dimensions{}
			}
			lbl := material.Body2(a.th, a.status)
			switch a.statusLv {
			case statusErr:
				lbl.Color = rgb(0xff6b6b)
			case statusWarn:
				lbl.Color = rgb(0xffcc66)
			case statusOK:
				lbl.Color = rgb(0x66d19e)
			}
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			txt := "● защита экрана активна"
			col := rgb(0x66d19e)
			if !a.protected {
				txt = "● защита экрана недоступна на этом устройстве"
				col = rgb(0xff6b6b)
			}
			lbl := material.Caption(a.th, txt)
			lbl.Color = col
			return lbl.Layout(gtx)
		}),
	)
}

func rgb(c uint32) color.NRGBA {
	return color.NRGBA{R: uint8(c >> 16), G: uint8(c >> 8), B: uint8(c), A: 0xff}
}
