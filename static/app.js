function pad(num) { return String(num).padStart(2, '0'); }

function toLocalIsoYYYYMMDD(localDate) {
  // Build YYYY-MM-DD using local time components to avoid UTC shifts
  const y = localDate.getFullYear();
  const m = pad(localDate.getMonth() + 1);
  const d = pad(localDate.getDate());
  return `${y}-${m}-${d}`;
}

function formatDDMMYYYY(localDate) {
  return `${pad(localDate.getDate())}/${pad(localDate.getMonth() + 1)}/${localDate.getFullYear()}`;
}

function renderCalendar(container, monthDate, todayIso, noteUrlBase) {
  const year = monthDate.getFullYear();
  const month = monthDate.getMonth();
  const start = new Date(year, month, 1);
  const end = new Date(year, month + 1, 0);
  const startWeekday = (start.getDay() + 6) % 7; // make Monday=0
  const totalDays = end.getDate();

  const grid = document.getElementById('calendar');
  const currentMonthEl = document.getElementById('currentMonth');
  grid.innerHTML = '';
  currentMonthEl.textContent = `${start.toLocaleString(undefined, { month: 'long' })} ${year}`;

  const daysOfWeek = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  for (const d of daysOfWeek) {
    const h = document.createElement('div');
    h.className = 'day heading';
    h.style.minHeight = 'auto';
    h.style.fontWeight = '700';
    h.textContent = d;
    grid.appendChild(h);
  }

  for (let i = 0; i < startWeekday; i++) {
    const spacer = document.createElement('div');
    grid.appendChild(spacer);
  }

  for (let d = 1; d <= totalDays; d++) {
    const el = document.createElement('div');
    el.className = 'day';
    const localDate = new Date(year, month, d);
    const iso = toLocalIsoYYYYMMDD(localDate);
    if (iso === todayIso) el.classList.add('today');
    el.innerHTML = `<div>${pad(d)}</div><div style="opacity:.6;font-size:12px">${formatDDMMYYYY(localDate)}</div>`;
    el.addEventListener('click', () => {
      const href = noteUrlBase.replace('__DATE__', iso);
      window.location.href = href;
    });
    grid.appendChild(el);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (!window.CALENDAR_INIT) return;
  const today = new Date(window.CALENDAR_INIT.today);
  let current = new Date(today.getFullYear(), today.getMonth(), 1);
  const noteUrlBase = window.CALENDAR_INIT.noteUrlBase;
  const container = document.getElementById('calendar');
  if (!container) return;

  const render = () => renderCalendar(container, current, window.CALENDAR_INIT.today, noteUrlBase);
  render();
  document.getElementById('prevMonth').addEventListener('click', () => { current = new Date(current.getFullYear(), current.getMonth() - 1, 1); render(); });
  document.getElementById('nextMonth').addEventListener('click', () => { current = new Date(current.getFullYear(), current.getMonth() + 1, 1); render(); });
});


