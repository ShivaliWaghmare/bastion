(() => {
  'use strict';
  const { api, h, clear, $, toast, timeAgo, formatDate } = App;

  const els = {
    list: $('#note-list'), count: $('#note-count'), filter: $('#note-filter'),
    editor: $('#editor'), empty: $('#empty-state'), title: $('#note-title'), body: $('#note-body'),
    save: $('#save-note'), del: $('#delete-note'), meta: $('#note-meta'), chars: $('#body-count'), dirty: $('#dirty-flag'),
  };
  let notes = [];
  let currentId = null;
  let editing = false;
  let dirty = false;

  const setDirty = (v) => { dirty = v; els.dirty.hidden = !v; };
  const confirmDiscard = () => !dirty || window.confirm('Discard unsaved changes?');
  const updateChars = () => { els.chars.textContent = `${els.body.value.length} / 20000`; };

  function showEditor(show) {
    editing = show;
    els.editor.hidden = !show;
    els.empty.hidden = show;
  }

  function renderList() {
    clear(els.list);
    els.count.textContent = String(notes.length);
    const q = els.filter.value.trim().toLowerCase();
    const items = notes.filter((n) => n.title.toLowerCase().includes(q));
    if (!items.length) {
      els.list.append(h('li', { class: 'list-empty' }, q ? 'No matching notes.' : 'No notes yet.'));
      return;
    }
    for (const n of items) {
      els.list.append(
        h('li', null,
          h('button', { type: 'button', class: 'note-item', role: 'option', 'aria-selected': String(n.id === currentId), onclick: () => openNote(n.id) },
            h('span', { class: 't' }, n.title), // textContent — XSS-safe
            h('span', { class: 'm' }, `Updated ${timeAgo(n.updatedAt)}`))));
    }
  }

  async function loadList() {
    notes = (await api.get('/api/notes')).notes;
    renderList();
  }

  function fill(note) {
    showEditor(true);
    els.title.value = note ? note.title : '';
    els.body.value = note ? note.body : '';
    els.del.hidden = !note;
    els.meta.textContent = note ? `Created ${formatDate(note.createdAt)} · updated ${timeAgo(note.updatedAt)}` : 'New note · not saved yet';
    updateChars();
    setDirty(false);
  }

  async function openNote(id) {
    if (id === currentId && editing) return;
    if (!confirmDiscard()) return;
    try {
      const { note } = await api.get(`/api/notes/${encodeURIComponent(id)}`);
      currentId = note.id;
      fill(note);
      renderList();
    } catch (err) {
      toast(err.message, 'danger');
    }
  }

  function newNote() {
    if (!confirmDiscard()) return;
    currentId = null;
    fill(null);
    renderList();
    els.title.focus();
  }

  async function save(e) {
    if (e) e.preventDefault();
    const payload = { title: els.title.value.trim(), body: els.body.value };
    if (!payload.title) {
      toast('Give the note a title first.', 'danger');
      els.title.focus();
      return;
    }
    els.save.disabled = true;
    try {
      const { note } = currentId
        ? await api.put(`/api/notes/${encodeURIComponent(currentId)}`, payload)
        : await api.post('/api/notes', payload);
      currentId = note.id;
      await loadList();
      fill(note);
      toast('Encrypted and saved.', 'success');
    } catch (err) {
      toast(err.message, 'danger');
    } finally {
      els.save.disabled = false;
    }
  }

  async function remove() {
    if (!currentId || !window.confirm('Delete this note permanently?')) return;
    try {
      await api.del(`/api/notes/${encodeURIComponent(currentId)}`);
      currentId = null;
      setDirty(false);
      showEditor(false);
      await loadList();
      toast('Note deleted.', 'success');
    } catch (err) {
      toast(err.message, 'danger');
    }
  }

  $('#new-note').addEventListener('click', newNote);
  $('#empty-new').addEventListener('click', newNote);
  els.editor.addEventListener('submit', save);
  els.del.addEventListener('click', remove);
  els.filter.addEventListener('input', renderList);
  els.title.addEventListener('input', () => setDirty(true));
  els.body.addEventListener('input', () => { setDirty(true); updateChars(); });
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's' && editing) {
      e.preventDefault();
      save();
    }
  });
  window.addEventListener('beforeunload', (e) => {
    if (dirty) e.preventDefault();
  });

  App.ready.then((user) => {
    if (!user) return;
    showEditor(false);
    loadList().catch((err) => toast(err.message, 'danger'));
  });
})();
