package gui

import (
	"errors"
	"strings"

	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/awnumar/memguard"

	"zeropass/internal/vault"
)

type editForm struct {
	editing    bool
	fromDetail bool
	id         int64

	title    widget.Editor
	username widget.Editor
	url      widget.Editor
	notes    widget.Editor
	pw       *securePW

	genBtn    widget.Clickable
	saveBtn   widget.Clickable
	cancelBtn widget.Clickable

	generated bool
	focusReq  bool
	prevLens  [4]int
}

func newEditForm(m vault.EntryMeta, notes string, editing, fromDetail bool) *editForm {
	f := &editForm{editing: editing, fromDetail: fromDetail, id: m.ID}
	f.title.SingleLine = true
	f.username.SingleLine = true
	f.url.SingleLine = true
	f.title.SetText(m.Title)
	f.username.SetText(m.Username)
	f.url.SetText(m.URL)
	f.notes.SetText(notes)
	hint := "новый пароль"
	if editing {
		hint = "новый пароль (пусто — оставить прежний)"
	}
	f.pw = newSecurePW(hint)
	return f
}

func (f *editForm) focusFirst() { f.focusReq = true }

func (f *editForm) destroy() {
	if f.pw != nil {
		f.pw.destroy()
	}
	wipeEditor(&f.title)
	wipeEditor(&f.username)
	wipeEditor(&f.url)
	wipeEditor(&f.notes)
}

func wipeEditor(ed *widget.Editor) {
	if n := ed.Len(); n > 0 {
		ed.SetText(strings.Repeat("x", n))
	}
	ed.SetText("")
}

func (f *editForm) meta() vault.EntryMeta {
	return vault.EntryMeta{
		ID:       f.id,
		Title:    strings.TrimSpace(f.title.Text()),
		Username: strings.TrimSpace(f.username.Text()),
		URL:      strings.TrimSpace(f.url.Text()),
	}
}

func (f *editForm) passwordBytes() *memguard.LockedBuffer {
	if f.pw.runeCount() == 0 {
		return nil
	}
	return f.pw.export()
}

func (f *editForm) bumpIfTyping(a *App, gtx layout.Context) {
	lens := [4]int{
		f.title.Len(), f.username.Len(), f.url.Len(), f.notes.Len(),
	}
	if lens != f.prevLens {
		a.act(gtx)
		f.prevLens = lens
	}
}

func (a *App) layoutEdit(gtx layout.Context) layout.Dimensions {
	f := a.form
	if f.focusReq {
		gtx.Execute(key.FocusCmd{Tag: &f.title})
		f.focusReq = false
	}
	submit, pwChanged := f.pw.update(gtx)
	if pwChanged {
		a.act(gtx)
	}
	f.bumpIfTyping(a, gtx)

	if f.genBtn.Clicked(gtx) {
		a.act(gtx)
		pw, err := generatePassword(pwGenLen)
		if err != nil {
			a.setErr(err)
		} else {
			f.pw.setBytes(pw)
			f.generated = true
			a.setOK("Надёжный пароль создан")
		}
	}
	if f.cancelBtn.Clicked(gtx) {
		a.act(gtx)
		a.closeForm()
		return layout.Dimensions{}
	}
	if submit || f.saveBtn.Clicked(gtx) {
		a.act(gtx)
		a.saveForm()
		return layout.Dimensions{}
	}

	title := "Новая запись"
	if f.editing {
		title = "Редактирование записи"
	}

	editor := func(ed *widget.Editor, hint string) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			m := material.Editor(a.th, ed, hint)
			return widget.Border{Color: a.borderColor(), Width: unit.Dp(1), CornerRadius: unit.Dp(4)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.UniformInset(unit.Dp(8)).Layout(gtx, m.Layout)
				})
		})
	}

	pwHelp := "Пароль хранится только в защищённом виде."
	if f.generated {
		pwHelp = "Создан уникальный пароль из 20 символов."
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return a.header(gtx, title) }),
		vspace(12),
		a.label("Название"),
		vspace(2),
		editor(&f.title, "например, Почта"),
		vspace(8),
		a.label("Логин"),
		vspace(2),
		editor(&f.username, "имя пользователя или email"),
		vspace(8),
		a.label("URL"),
		vspace(2),
		editor(&f.url, "https://…"),
		vspace(8),
		a.label("Заметки"),
		vspace(2),
		editor(&f.notes, ""),
		vspace(8),
		a.label("Пароль"),
		vspace(2),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return f.pw.layout(gtx, a.th) }),
		vspace(2),
		a.caption(pwHelp),
		vspace(14),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(a.button(&f.saveBtn, "Сохранить")),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&f.genBtn, "Сгенерировать")),
				layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
				layout.Rigid(a.button(&f.cancelBtn, "Отмена")),
			)
		}),
		vspace(16),
		layout.Rigid(a.statusBar),
	)
}

func (a *App) closeForm() {
	fromDetail := a.form.fromDetail
	a.form.destroy()
	a.form = nil
	if fromDetail {
		a.stage = stageDetail
	} else {
		a.stage = stageList
	}
	a.clearStatus()
}

func (a *App) saveForm() {
	f := a.form
	meta := f.meta()
	if strings.TrimSpace(meta.Title) == "" {
		a.setErr(errors.New("название записи не может быть пустым"))
		return
	}
	pw := f.passwordBytes()
	if pw != nil {
		defer pw.Destroy()
	}
	var raw []byte
	if pw != nil {
		raw = pw.Bytes()
	}
	notes := []byte(f.notes.Text())
	defer memguard.WipeBytes(notes)
	err := a.vault.Update(func(st *vault.Store) error {

		if f.editing {
			if err := st.UpdateMeta(meta); err != nil {
				return err
			}
			if pw != nil {
				if err := st.SetPassword(meta.ID, raw); err != nil {
					return err
				}
			}
			if err := st.SetNotes(meta.ID, notes); err != nil {
				return err
			}
		} else {
			if pw == nil {
				return errors.New("нужен пароль: введите или нажмите «Сгенерировать»")
			}
			id, err := st.Add(meta, raw)
			if err != nil {
				return err
			}
			meta.ID = id
			if err := st.SetNotes(id, notes); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		a.setErr(err)
		return
	}

	fromDetail := f.fromDetail
	f.destroy()
	a.form = nil
	a.rebuildRows()
	if fromDetail {
		a.detailID = meta.ID
		a.detailMeta = meta
		a.stage = stageDetail
	} else {
		a.stage = stageList
	}
	a.setOK("Изменения сохранены")
}
