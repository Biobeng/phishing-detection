const form = document.getElementById('check-form');
const notice = document.getElementById('notice');
const runBtn = document.getElementById('run');
const result = document.getElementById('result');
const tpl = document.getElementById('tpl-result');
let mode = 'link';

const WORDS = {
  phishing: { title: 'Treat this as phishing', advice: 'Do not sign in, reply or open anything it asks you to open.' },
  suspicious: { title: 'Not clear cut', advice: 'Enough here to be careful. Reach the sender another way before you act on it.' },
  legitimate: { title: 'Nothing here reads as phishing', advice: 'Normal care still applies. No tool catches everything.' }
};

function setMode(next) {
  mode = next;
  document.querySelectorAll('.tab').forEach(t => {
    const on = t.dataset.mode === next;
    t.classList.toggle('is-on', on);
    t.setAttribute('aria-selected', on);
  });
  document.querySelectorAll('.field').forEach(f => { f.hidden = f.dataset.for !== next; });
  runBtn.querySelector('.run-label').textContent = next === 'link' ? 'Scan this link' : 'Scan this message';
  hideNotice();
}

function hideNotice() { notice.hidden = true; notice.textContent = ''; }

function showNotice(text) { notice.textContent = text; notice.hidden = false; }

function row(name, pct) {
  const li = document.createElement('li');
  li.innerHTML = `<span></span><span class="bar"><i></i></span><span class="num"></span>`;
  li.children[0].textContent = name;
  li.querySelector('i').style.width = pct + '%';
  li.children[2].textContent = pct.toFixed(0) + '%';
  return li;
}

function signalRow(s) {
  const li = document.createElement('li');
  li.innerHTML = `<span class="label"></span><span class="value"></span>`;
  li.children[0].textContent = s.label;
  li.children[1].textContent = s.value;
  if (s.flag) li.children[1].classList.add('flagged');
  return li;
}

function render(data) {
  const node = tpl.content.cloneNode(true);
  const box = node.querySelector('.reading');
  box.classList.add('is-' + data.verdict);

  box.querySelector('.read-as').textContent = data.read_as;
  box.querySelector('.verdict').textContent = WORDS[data.verdict].title;
  box.querySelector('.advice').textContent = WORDS[data.verdict].advice;

  const low = box.querySelector('.foot-low');
  const high = box.querySelector('.foot-high');
  low.textContent = data.marks.low;
  high.textContent = data.marks.high;
  low.style.left = data.marks.low + '%';
  high.style.left = data.marks.high + '%';
  const segs = box.querySelectorAll('.seg');
  segs[0].style.flex = data.marks.low;
  segs[1].style.flex = data.marks.high - data.marks.low;
  segs[2].style.flex = 100 - data.marks.high;

  const marker = box.querySelector('.meter-knob');
  marker.style.left = '0%';
  marker.querySelector('.marker-num').textContent = data.score.toFixed(0);

  const models = box.querySelector('.models');
  data.models.forEach(m => models.appendChild(row(m.name, m.score)));
  const signals = box.querySelector('.signals');
  data.signals.forEach(s => signals.appendChild(signalRow(s)));

  box.querySelector('.again').addEventListener('click', () => {
    const field = document.getElementById(mode === 'link' ? 'link' : 'body');
    field.value = '';
    field.focus();
  });

  result.replaceChildren(node);
  requestAnimationFrame(() => { marker.style.left = data.score + '%'; });
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideNotice();
  const payload = {
    mode,
    text: mode === 'link' ? document.getElementById('link').value : document.getElementById('body').value,
    subject: document.getElementById('subject').value
  };
  runBtn.disabled = true;
  runBtn.querySelector('.run-label').textContent = 'Scanning…';
  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) { showNotice(data.error); } else { render(data); }
  } catch (err) {
    showNotice('The server did not answer. Check that it is still running, then try again.');
  }
  runBtn.disabled = false;
  runBtn.querySelector('.run-label').textContent = mode === 'link' ? 'Scan this link' : 'Scan this message';
});

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => setMode(t.dataset.mode)));
setMode('link');
