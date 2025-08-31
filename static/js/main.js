async function toggleTask(id) {
  const res = await fetch(`/task/${id}/toggle`, { method: 'POST' });
  if (res.ok) {
    const data = await res.json();
    const cb = document.getElementById(`task-done-${id}`);
    if (cb) cb.checked = data.done;
  }
}

async function deleteTask(id) {
  if (!confirm('Delete task?')) return;
  const res = await fetch(`/task/${id}/delete`, { method: 'POST' });
  if (res.ok) {
    const li = document.getElementById(`task-item-${id}`);
    if (li) li.remove();
  }
}
