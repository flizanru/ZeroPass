package gui

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"image"
	"image/color"
	"os"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"zeropass/internal/secure"
	"zeropass/internal/vault"
)

type vaultStatus int

const (
	vaultAbsent vaultStatus = iota
	vaultPresent
	vaultOnlyBackup
	vaultError
)

func vaultState(path string) (vaultStatus, error) {
	_, mainErr := os.Stat(path)
	_, bakErr := os.Stat(path + vault.BackupSuffix)
	switch {
	case mainErr == nil:
		return vaultPresent, nil
	case bakErr == nil:
		return vaultOnlyBackup, nil
	case errors.Is(mainErr, os.ErrNotExist):
		return vaultAbsent, nil
	default:
		return vaultError, fmt.Errorf("доступ к %s: %w", path, mainErr)
	}
}

func (a *App) hasBackup() bool {
	_, err := os.Stat(a.path + vault.BackupSuffix)
	return err == nil
}

func vspace(dp int) layout.FlexChild {
	return layout.Rigid(layout.Spacer{Height: unit.Dp(dp)}.Layout)
}

func (a *App) caption(txt string) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		lbl := material.Caption(a.th, txt)
		lbl.Color = a.th.Fg
		lbl.Color.A = 0xaa
		return lbl.Layout(gtx)
	})
}

func (a *App) label(txt string) layout.FlexChild {
	return layout.Rigid(material.Body2(a.th, txt).Layout)
}

func (a *App) button(btn *widget.Clickable, txt string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return material.Button(a.th, btn, txt).Layout(gtx)
	}
}

func (a *App) layoutAuth(gtx layout.Context) layout.Dimensions {
	if a.busy {
		return a.layoutBusy(gtx)
	}
	create := a.stage == stageCreate

	submit1, changed1 := a.pw1.update(gtx)
	if changed1 {
		a.act(gtx)
	}
	submit2, changed2 := false, false
	if create {
		submit2, changed2 = a.pw2.update(gtx)
		if changed2 {
			a.act(gtx)
		}
	}
	if submit1 {
		a.act(gtx)
		if create {
			a.pw2.focus()
		} else {
			a.startUnlock()
		}
	}
	if submit2 {
		a.act(gtx)
		a.startCreate()
	}
	if a.primaryBtn.Clicked(gtx) {
		a.act(gtx)
		if create {
			a.startCreate()
		} else {
			a.startUnlock()
		}
	}
	if a.busy {
		return a.layoutBusy(gtx)
	}

	title, hint, btnTxt := productName, "Введите мастер-пароль, чтобы продолжить.", "Войти"
	if create {
		title = "Добро пожаловать в " + productName
		hint = "Создайте мастер-пароль — он будет единственным ключом к вашим данным."
		btnTxt = "Начать работу"
	}

	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.header(gtx, title) }),
		vspace(6),
		a.caption(hint),
		vspace(18),
		a.label("Мастер-пароль"),
		vspace(4),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.pw1.layout(gtx, a.th) }),
	}
	if create {
		children = append(children,
			vspace(10),
			a.label("Повторите пароль"),
			vspace(4),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.pw2.layout(gtx, a.th) }),
		)
	}
	children = append(children,
		vspace(16),
		layout.Rigid(a.button(&a.primaryBtn, btnTxt)),
		vspace(20),
		layout.Rigid(a.statusBar),
	)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func (a *App) header(gtx layout.Context, title string) layout.Dimensions {
	return material.H6(a.th, title).Layout(gtx)
}

type authResult struct {
	v      *vault.Vault
	err    error
	create bool
}

func (a *App) startUnlock() {
	if a.busy {
		return
	}
	if a.pw1.runeCount() == 0 {
		a.setErr(errors.New("введите мастер-пароль"))
		return
	}
	pw := a.pw1.export()
	a.pw1.clear()
	a.beginAuth("Проверяем мастер-пароль…")
	ch, path := a.authCh, a.path
	go func() {
		defer exitOnPanic()
		restore := kdfCPUCap()
		v, err := vault.Unlock(path, pw)
		restore()
		pw.Destroy()
		ch <- authResult{v: v, err: err, create: false}
		a.w.Invalidate()
	}()
}

func (a *App) startCreate() {
	if a.busy {
		return
	}
	if a.pw1.runeCount() < 8 {
		a.setErr(errors.New("мастер-пароль короче 8 символов"))
		a.pw1.focus()
		return
	}
	b1 := a.pw1.export()
	b2 := a.pw2.export()
	same := subtle.ConstantTimeCompare(b1.Bytes(), b2.Bytes()) == 1
	b2.Destroy()
	if !same {
		b1.Destroy()
		a.setErr(errors.New("пароли не совпадают"))
		a.pw2.clear()
		a.pw2.focus()
		return
	}
	a.pw1.clear()
	a.pw2.clear()
	a.beginAuth("Подготавливаем защищённое пространство…")
	ch, path := a.authCh, a.path
	go func() {
		defer exitOnPanic()
		restore := kdfCPUCap()
		v, err := vault.Create(path, b1)
		restore()
		b1.Destroy()
		ch <- authResult{v: v, err: err, create: true}
		a.w.Invalidate()
	}()
}

func (a *App) beginAuth(msg string) {
	a.busy = true
	a.busyMsg = msg
	a.authCh = make(chan authResult, 1)
	a.clearStatus()
}

func (a *App) onAuthResult(res authResult) {
	a.busy = false
	a.busyMsg = ""
	a.authCh = nil

	if res.err != nil {
		if errors.Is(res.err, vault.ErrConflict) || errors.Is(res.err, vault.ErrExists) {
			a.setErr(res.err)
			a.pw1.focus()
			return
		}
		if res.create {
			a.setErr(errors.New("Не удалось создать защищённое пространство. Проверьте доступность носителя и повторите попытку."))
		} else if a.hasBackup() {
			a.setErr(errors.New("Не удалось открыть хранилище. Проверьте мастер-пароль; доступна резервная копия данных."))
		} else {
			a.setErr(errors.New("Не удалось открыть хранилище. Проверьте мастер-пароль и повторите попытку."))
		}
		a.pw1.focus()
		return
	}
	a.vault = res.v
	a.lastAct = time.Now()
	a.rebuildRows()
	a.stage = stageList
	if res.create {
		a.setOK("Защищённое пространство готово")
	} else {
		a.clearStatus()
	}
	a.checkSession(time.Now())
}

func (a *App) layoutBusy(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						sz := gtx.Dp(unit.Dp(48))
						gtx.Constraints = layout.Exact(image.Pt(sz, sz))
						return material.Loader(a.th).Layout(gtx)
					}),
					vspace(18),
					layout.Rigid(material.Body1(a.th, a.busyMsg).Layout),
					vspace(6),
					a.caption("Надёжная проверка может занять несколько секунд"),
				)
			})
		}),
	)
}

func (a *App) layoutRecover(gtx layout.Context) layout.Dimensions {
	if a.recoverBtn.Clicked(gtx) {
		a.act(gtx)
		if err := vault.Recover(a.path); err != nil {
			a.setErr(errors.New("Не удалось восстановить данные. Проверьте доступность носителя и повторите попытку."))
		} else {
			a.stage = stageUnlock
			a.pw1.focus()
			a.setOK("Резервная копия восстановлена")
		}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.header(gtx, "Требуется восстановление")
		}),
		vspace(10),
		a.caption("Основное хранилище недоступно, но найдена сохранённая резервная копия."),
		vspace(4),
		a.caption("ZeroPass может безопасно восстановить её и вернуть доступ к данным."),
		vspace(18),
		layout.Rigid(a.button(&a.recoverBtn, "Восстановить данные")),
		vspace(20),
		layout.Rigid(a.statusBar),
	)
}

func (a *App) rebuildRows() {
	a.rows = nil
	if a.vault == nil {
		return
	}
	metas, err := a.vault.Store.List()
	if err != nil {
		a.setErr(err)
		return
	}
	a.rows = make([]entryRow, len(metas))
	for i, m := range metas {
		a.rows[i] = entryRow{meta: m}
	}
}

func (a *App) visibleRows(q string) []int {
	out := make([]int, 0, len(a.rows))
	for i := range a.rows {
		m := a.rows[i].meta
		if q == "" || strings.Contains(strings.ToLower(m.Title+" "+m.Username+" "+m.URL), q) {
			out = append(out, i)
		}
	}
	return out
}

func (a *App) layoutList(gtx layout.Context) layout.Dimensions {
	if a.addBtn.Clicked(gtx) {
		a.act(gtx)
		a.form = newEditForm(vault.EntryMeta{}, "", false, false)
		a.form.focusFirst()
		a.stage = stageEdit
		a.clearStatus()
	}
	if a.lockBtn.Clicked(gtx) {
		a.act(gtx)
		a.lock("Сеанс безопасно заблокирован")
		return layout.Dimensions{}
	}

	q := strings.ToLower(strings.TrimSpace(a.search.Text()))
	visible := a.visibleRows(q)

	for _, idx := range visible {
		if a.rows[idx].click.Clicked(gtx) {
			a.act(gtx)
			a.openDetail(a.rows[idx].meta)
		}
	}

	topBar := layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return a.header(gtx, productName)
			}),
			layout.Rigid(a.button(&a.addBtn, "Добавить")),
			layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
			layout.Rigid(a.button(&a.lockBtn, "Заблокировать")),
		)
	})

	searchBar := layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		ed := material.Editor(a.th, &a.search, "Фильтр по названию, логину, URL…")
		return widget.Border{Color: a.borderColor(), Width: unit.Dp(1), CornerRadius: unit.Dp(4)}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(8)).Layout(gtx, ed.Layout)
			})
	})

	listArea := layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
		if len(visible) == 0 {
			msg := "Пока нет записей. Нажмите «Добавить»."
			if q != "" {
				msg = "Ничего не найдено."
			}
			return layout.UniformInset(unit.Dp(12)).Layout(gtx, material.Body2(a.th, msg).Layout)
		}
		return material.List(a.th, &a.list).Layout(gtx, len(visible), func(gtx layout.Context, i int) layout.Dimensions {
			return a.layoutRow(gtx, &a.rows[visible[i]])
		})
	})

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		topBar,
		vspace(10),
		searchBar,
		vspace(8),
		listArea,
		vspace(8),
		layout.Rigid(a.statusBar),
	)
}

func (a *App) layoutRow(gtx layout.Context, row *entryRow) layout.Dimensions {
	target := boolf(row.click.Hovered())
	row.hover = animateTo(row.hover, target, a.dt*10)
	if row.hover != target {
		gtx.Execute(op.InvalidateCmd{})
	}
	h := row.hover

	return row.click.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				sz := gtx.Constraints.Min
				if h > 0 {
					overlay := a.th.Fg
					overlay.A = uint8(h * 0x24)
					st := clip.UniformRRect(image.Rectangle{Max: sz}, gtx.Dp(unit.Dp(6))).Push(gtx.Ops)
					paint.Fill(gtx.Ops, overlay)
					st.Pop()

					barW := gtx.Dp(unit.Dp(3))
					barH := int(float32(sz.Y) * h)
					y0 := (sz.Y - barH) / 2
					accent := a.th.ContrastBg
					accent.A = uint8(h * 0xff)
					bar := clip.UniformRRect(image.Rect(0, y0, barW, y0+barH), barW/2).Push(gtx.Ops)
					paint.Fill(gtx.Ops, accent)
					bar.Pop()
				}
				return layout.Dimensions{Size: sz}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{
					Top: unit.Dp(10), Bottom: unit.Dp(10),
					Left: unit.Dp(10 + 8*h), Right: unit.Dp(10),
				}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(material.Body1(a.th, row.meta.Title).Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							lbl := material.Caption(a.th, subtitle(row.meta))
							lbl.Color = a.th.Fg
							lbl.Color.A = 0xaa
							return lbl.Layout(gtx)
						}),
					)
				})
			}),
		)
	})
}

func animateTo(cur, target, step float32) float32 {
	switch {
	case cur < target:
		if cur += step; cur > target {
			cur = target
		}
	case cur > target:
		if cur -= step; cur < target {
			cur = target
		}
	}
	return cur
}

func boolf(b bool) float32 {
	if b {
		return 1
	}
	return 0
}

func subtitle(m vault.EntryMeta) string {
	switch {
	case m.Username != "" && m.URL != "":
		return m.Username + " · " + m.URL
	case m.Username != "":
		return m.Username
	case m.URL != "":
		return m.URL
	}
	return "—"
}

func (a *App) borderColor() color.NRGBA {
	col := a.th.Fg
	col.A = 0x60
	return col
}

func (a *App) openDetail(m vault.EntryMeta) {
	a.destroyRevealed()
	a.destroyNotesRevealed()
	a.detailID = m.ID
	a.detailMeta = m
	a.stage = stageDetail
	a.clearStatus()
}

func (a *App) layoutDetail(gtx layout.Context) layout.Dimensions {
	if a.backBtn.Clicked(gtx) {
		a.act(gtx)
		a.destroyRevealed()
		a.destroyNotesRevealed()
		a.stage = stageList
		a.clearStatus()
		return layout.Dimensions{}
	}
	if a.showBtn.Clicked(gtx) {
		a.act(gtx)
		if a.revealed != nil {
			a.destroyRevealed()
		} else if b, err := a.vault.Store.Password(a.detailID); err != nil {
			a.setErr(err)
		} else {
			a.revealed = b
			a.revealedAt = gtx.Now
		}
	}
	if a.showNotesBtn.Clicked(gtx) {
		a.act(gtx)
		if a.notesRevealed != nil {
			a.destroyNotesRevealed()
		} else if b, err := a.vault.Store.Notes(a.detailID); err != nil {
			a.setErr(err)
		} else {
			a.notesRevealed = b
			a.notesRevealedAt = gtx.Now
		}
	}
	if a.copyBtn.Clicked(gtx) {
		a.act(gtx)
		a.copyPassword()
	}
	if a.editBtn.Clicked(gtx) {
		a.act(gtx)
		a.destroyRevealed()
		notes, err := a.vault.Store.Notes(a.detailID)
		if err != nil {
			a.setErr(err)
			return layout.Dimensions{}
		}
		noteText := ""
		if notes != nil {
			noteText = string(notes.Bytes())
			notes.Destroy()
		}
		a.destroyNotesRevealed()
		a.form = newEditForm(a.detailMeta, noteText, true, true)
		a.form.focusFirst()
		a.stage = stageEdit
		a.clearStatus()
	}
	if a.delBtn.Clicked(gtx) {
		a.act(gtx)
		a.destroyRevealed()
		a.destroyNotesRevealed()
		a.deleteID = a.detailID
		a.deleteName = a.detailMeta.Title
		a.stage = stageConfirmDelete
		a.clearStatus()
	}

	m := a.detailMeta
	showTxt := "Показать"
	if a.revealed != nil {
		showTxt = "Скрыть"
	}
	notesText := "••••••••••••"
	showNotesTxt := "Показать заметки"
	if a.notesRevealed != nil {
		notesText = valueOrDash(string(a.notesRevealed.Bytes()))
		showNotesTxt = "Скрыть заметки"
	}

	field := func(name, val string) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(unit.Dp(90))
					lbl := material.Body2(a.th, name)
					lbl.Color = a.th.Fg
					lbl.Color.A = 0xaa
					return lbl.Layout(gtx)
				}),
				layout.Flexed(1, material.Body1(a.th, valueOrDash(val)).Layout),
			)
		})
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.header(gtx, m.Title) }),
		vspace(14),
		field("Логин", m.Username),
		vspace(6),
		field("URL", m.URL),
		vspace(6),
		field("Заметки", notesText),
		vspace(6),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(unit.Dp(90))
					lbl := material.Body2(a.th, "Пароль")
					lbl.Color = a.th.Fg
					lbl.Color.A = 0xaa
					return lbl.Layout(gtx)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if a.revealed != nil {
						return a.pwView.layout(gtx, a.th, a.revealed)
					}
					return material.Body1(a.th, "••••••••••••").Layout(gtx)
				}),
			)
		}),
		vspace(18),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(a.button(&a.showBtn, showTxt)),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&a.showNotesBtn, showNotesTxt)),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&a.copyBtn, "Копировать")),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&a.editBtn, "Править")),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&a.delBtn, "Удалить")),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&a.backBtn, "Назад")),
			)
		}),
		vspace(20),
		layout.Rigid(a.statusBar),
	)
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func (a *App) copyPassword() {
	b, err := a.vault.Store.Password(a.detailID)
	if err != nil {
		a.setErr(err)
		return
	}
	warn, err := secure.CopySensitive(a.hwnd, b.Bytes(), clipboardTTL)
	b.Destroy()
	if err != nil {
		a.setErr(err)
		return
	}
	msg := fmt.Sprintf("Пароль скопирован и будет удалён из буфера через %d секунд", int(clipboardTTL.Seconds()))
	if warn != "" {
		a.setWarn(msg + " · " + warn)
	} else {
		a.setOK(msg)
	}
}

func (a *App) layoutConfirm(gtx layout.Context) layout.Dimensions {
	if a.yesBtn.Clicked(gtx) {
		a.act(gtx)
		a.doDelete()
	}
	if a.noBtn.Clicked(gtx) {
		a.act(gtx)
		a.deleteID, a.deleteName = 0, ""
		a.stage = stageList
		a.clearStatus()
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.header(gtx, "Удалить запись?") }),
		vspace(12),
		a.caption("Запись «"+a.deleteName+"» будет удалена без возможности восстановления."),
		vspace(18),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(a.button(&a.yesBtn, "Удалить")),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&a.noBtn, "Отмена")),
			)
		}),
		vspace(20),
		layout.Rigid(a.statusBar),
	)
}

func (a *App) doDelete() {
	id := a.deleteID
	if err := a.vault.Update(func(st *vault.Store) error { return st.Delete(id) }); err != nil {
		a.setErr(err)
		return
	}
	a.deleteID, a.deleteName = 0, ""
	a.setOK("Запись удалена")
	a.rebuildRows()
	a.stage = stageList
}
