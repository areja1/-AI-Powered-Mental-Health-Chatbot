document.addEventListener('DOMContentLoaded', () => {
  const stream = document.getElementById('stream');
  const form = document.getElementById('sendForm');
  const input = document.getElementById('prompt');
  const sendBtn = document.getElementById('sendBtn');
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF = csrfMeta ? csrfMeta.getAttribute('content') : '';

  function el(tag, cls, text){ const n = document.createElement(tag); if (cls) n.className = cls; if (text) n.textContent = text; return n; }
  function scroll() { stream.scrollTop = stream.scrollHeight; }
  function toast(msg, type='info'){
    const box = document.createElement('div'); box.className = `toast ${type}`; box.textContent = msg;
    document.querySelector('.toasts')?.appendChild(box);
    setTimeout(()=>{ box.style.opacity='0'; box.style.transform='translateX(20px)'; setTimeout(()=>box.remove(), 450); }, 4200);
  }

  function typingNode(){
    const wrap = el('div','msg bot');
    const t = el('div','typing');
    t.appendChild(el('div','dot')); t.appendChild(el('div','dot')); t.appendChild(el('div','dot'));
    wrap.appendChild(t);
    return wrap;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = (input.value || '').trim();
    if (!text) return;

    // user bubble
    stream.appendChild(el('div','msg user', text));
    scroll();
    input.value = '';
    input.focus();

    // typing bubble
    const typing = typingNode();
    stream.appendChild(typing);
    sendBtn.disabled = true;

    try {
      const res = await fetch('/chatbot', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': CSRF
        },
        body: JSON.stringify({ message: text })
      });
      const data = await res.json();
      typing.remove();
      const klass = data.crisis ? 'msg bot crisis' : 'msg bot';
      stream.appendChild(el('div', klass, data.reply || ''));
      scroll();
      if (!res.ok) toast('The AI service returned an error.', 'warning');
    } catch (err){
      typing.remove();
      stream.appendChild(el('div','msg bot','Sorry, I’m having trouble right now.'));
      toast('Network error. Please try again.', 'danger');
    } finally {
      sendBtn.disabled = false;
    }
  });
});
