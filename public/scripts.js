let myPrivateKey = null;
let currentDialogId = null;
let currentDialogPartnerId = null;
let authToken = localStorage.getItem('auth_token');
let currentUser = JSON.parse(localStorage.getItem('user') || '{}');
let pollTimer = null;
let lastReadMessageId = JSON.parse(localStorage.getItem('lastReadMessages') || '{}');
let unreadCounts = {};
let dialogElements = {};
let pendingElements = {};
let displayedMessageIds = {};
let isScrollingUp = false; //  Для сохранения скролла


let newMessageCount = 0;
let isAtBottom = true;




// Проверка позиции скролла
const checkScrollPosition = () => {
  const container = document.getElementById('messages');
  if (!container) return true;
  
  const scrollThreshold = 100;
  const isBottom = container.scrollHeight - container.scrollTop - container.clientHeight < scrollThreshold;
  
  isAtBottom = isBottom;
  
  // Скрываем бейдж ТОЛЬКО когда доскроллили до конца
  if (isBottom && newMessageCount > 0) {
    newMessageCount = 0;
    const badge = document.getElementById('new-msg-badge');
    if (badge) badge.classList.remove('visible');
  }
  
  return isBottom;
};

//  Показать бейдж
window.showNewMsgBadge = (count) => {
  const badge = document.getElementById('new-msg-badge');
  const countEl = document.getElementById('badge-count');
  if (!badge) return;
  
  if (count > 0 && !isAtBottom) {
    countEl.textContent = count > 9 ? '9+' : count;
    badge.classList.add('visible');
    console.log(' Бейдж показан:', count, 'сообщений');
  }
};

//  Прокрутка вниз
window.scrollToBottom = () => {
  const container = document.getElementById('messages');
  if (!container) return;
  container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
  newMessageCount = 0;
  const badge = document.getElementById('new-msg-badge');
  if (badge) badge.classList.remove('visible');
};

//  Настройка слушателя скролла
const setupScrollListener = () => {
  const container = document.getElementById('messages');
  if (!container) return;
  
  container.addEventListener('scroll', () => {
    checkScrollPosition();
  });
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupScrollListener);
} else {
  setupScrollListener();
}



const formatMessageTime = (dateString) => {
  try {
    if (!dateString) return '';
    
    //  Сервер отдаёт UTC без суффикса. Преобразуем в ISO с 'Z', чтобы JS понял, что это UTC
    const isoString = dateString.includes('Z') ? dateString : dateString.replace(' ', 'T') + 'Z';
    const date = new Date(isoString);

    if (isNaN(date.getTime())) return '';

    const now = new Date();
    
    //  toLocaleTimeString автоматически конвертирует UTC → ваше локальное время
    const timeStr = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

    // "Сегодня"
    const isToday = date.getDate() === now.getDate() && 
                    date.getMonth() === now.getMonth() && 
                    date.getFullYear() === now.getFullYear();
    if (isToday) return timeStr;

    // "Вчера"
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    const isYesterday = date.getDate() === yesterday.getDate() && 
                        date.getMonth() === yesterday.getMonth() && 
                        date.getFullYear() === yesterday.getFullYear();
    if (isYesterday) return 'вчера, ' + timeStr;

    // Дата + время
    const dateStr = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' });
    if (date.getFullYear() === now.getFullYear()) return `${dateStr}, ${timeStr}`;

    const fullDateStr = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit' });
    return `${fullDateStr}, ${timeStr}`;
  } catch (e) {
    console.error('Time format error:', e);
    return '';
  }
};


const api = async (path, opts = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const res = await fetch(path, { ...opts, headers });
  const data = await res.json().catch(() => ({ error: 'Invalid response' }));
  if (!res.ok) throw new Error(data.error || 'Error');
  return data;
};

const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;

const saveKey = async (id, cryptoKey) => {
  const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
  localStorage.setItem('crypto_key_' + id, JSON.stringify(jwk));
};

const loadKey = async (id) => {
  const jwkStr = localStorage.getItem('crypto_key_' + id);
  if (!jwkStr) return null;
  return await crypto.subtle.importKey('jwk', JSON.parse(jwkStr), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
};

const initCrypto = async () => {
  console.log('🔑 initCrypto started...');
  
  myPrivateKey = await loadKey('priv');
  
  if (!myPrivateKey) {
    console.log('🔑 Generating NEW key pair...');
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    myPrivateKey = kp.privateKey;
    await saveKey('priv', myPrivateKey);
    
    const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const pubKeyStr = JSON.stringify(pubJwk);
    
    console.log('📤 Sending to /api/key...');
    
    try {
      const response = await api('/api/key', { 
        method: 'POST', 
        body: JSON.stringify({ public_key: pubKeyStr }) 
      });
      console.log('✅ Key saved to server:', response);
    } catch (e) {
      console.error('❌ Failed to save key:', e);
    }
  } else {
    console.log('✅ Loaded existing private key from localStorage');
  }
};

const deriveKey = async (partnerJwkStr) => {
  const jwkObj = typeof partnerJwkStr === 'string' ? JSON.parse(partnerJwkStr) : partnerJwkStr;
  const pubKey = await crypto.subtle.importKey('jwk', jwkObj, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  return crypto.subtle.deriveKey({ name: 'ECDH', public: pubKey }, myPrivateKey, { name: 'AES-GCM', length: 128 }, true, ['encrypt', 'decrypt']);
};

const updateBadge = (dialogId, count) => {
  const el = dialogElements[dialogId];
  if (!el) return;
  const badge = el.querySelector('.unread-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline-block';
    badge.classList.add('new-message');
    setTimeout(() => badge.classList.remove('new-message'), 2000);
  } else {
    badge.textContent = '';
    badge.style.display = 'none';
  }
};

const refreshCounters = async () => {
  try {
    const dialogs = await api('/api/dialogs');
    unreadCounts = {};
    for (const dialog of dialogs) {
      const msgs = await api(`/api/messages/${dialog.id}`);
      if (msgs.length > 0) {
        const lastMsg = msgs[msgs.length - 1];
        const lastReadId = lastReadMessageId[String(dialog.id)] || 0;
        if (lastMsg.id > lastReadId && lastMsg.sender_id !== currentUser.id) {
          const unread = msgs.filter(m => m.id > lastReadId && m.sender_id !== currentUser.id).length;
          if (unread > 0) unreadCounts[dialog.id] = unread;
        }
      }
      updateBadge(dialog.id, unreadCounts[dialog.id] || 0);
    }
  } catch (e) { console.error(e); }
};

const checkNewMessages = async () => {
  try {
    const dialogs = await api('/api/dialogs');
    for (const dialog of dialogs) {
      try {
        const msgs = await api(`/api/messages/${dialog.id}`);
        const storedId = lastReadMessageId[String(dialog.id)] || 0;
        if (msgs.length === 0) {
          if (unreadCounts[dialog.id] !== 0) { unreadCounts[dialog.id] = 0; updateBadge(dialog.id, 0); }
          continue;
        }
        const lastMsg = msgs[msgs.length - 1];
        if (lastMsg.id > storedId && lastMsg.sender_id !== currentUser.id) {
          const unread = msgs.filter(m => m.id > storedId && m.sender_id !== currentUser.id).length;
          if (unread !== unreadCounts[dialog.id]) { unreadCounts[dialog.id] = unread; updateBadge(dialog.id, unread); }
        }
      } catch (e) {}
    }
  } catch (e) { console.error(e); }
};

window.handleAuth = async () => {
  const n = document.getElementById('nickname').value.trim();
  const p = document.getElementById('password').value.trim();
  const msg = document.getElementById('auth-msg');
  if (!n || !p) return msg.textContent = 'Заполните поля';
  try {
    const data = await api('/api/auth', { method: 'POST', body: JSON.stringify({ nickname: n, password: p }) });
    authToken = data.token;
    currentUser = { id: data.id, nickname: data.nickname };
    localStorage.setItem('auth_token', authToken);
    localStorage.setItem('user', JSON.stringify(currentUser));
    startApp();
  } catch (e) { msg.textContent = e.message; }
};

const startApp = async () => {
  if (!authToken || !currentUser.id) {
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('app-screen').classList.add('hidden');
    return;
  }
  
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('app-screen').classList.remove('hidden');
  document.getElementById('menu-username').textContent = currentUser.nickname;
  
  await initCrypto(); // ✅ ЭТА СТРОКА ДОЛЖНА БЫТЬ!
  await loadDialogs();
  await loadPending();
  await refreshCounters();
  
  if (pollTimer) clearInterval(pollTimer);
pollTimer = setInterval(() => { 
  loadPending(); 
  loadDialogs(); //  Проверяем, не удалили ли диалог
  checkNewMessages(); 
  if (currentDialogId) loadNewMessages();
}, 3000);
};

window.searchUser = async () => {
  const q = document.getElementById('search-input').value.trim();
  const box = document.getElementById('search-results');
  if (q.length < 2) { box.classList.remove('active'); return; }
  try {
    const users = await api(`/api/users/search?q=${q}`);
    box.innerHTML = users.map(u => `
      <div class="search-item">
        <span>${u.nickname}</span>
        <button class="btn-sm" onclick="window.sendReq('${u.nickname}', this)">Добавить</button>
      </div>`).join('');
    box.classList.add('active');
  } catch (e) { console.error(e); }
};

window.sendReq = async (nick, btn) => {
  try {
    await api('/api/contact/request', { method: 'POST', body: JSON.stringify({ to_nickname: nick }) });
    btn.textContent = ''; btn.disabled = true;
    setTimeout(() => {
      document.getElementById('search-results').classList.remove('active');
      document.getElementById('search-input').value = '';
    }, 500);
  } catch (e) { alert(e.message); }
};

const loadPending = async () => {
  try {
    const list = await api('/api/contacts/pending');
    const box = document.getElementById('pending-box');
    const countEl = document.getElementById('pending-count');
    const listEl = document.getElementById('pending-list');
    countEl.textContent = list.length > 0 ? `(${list.length})` : '';
    if (list.length === 0) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    const currentIds = new Set();
    list.forEach(r => {
      currentIds.add(r.from_id);
      if (!pendingElements[r.from_id]) {
        const div = document.createElement('div');
        div.className = 'pending-item';
        div.innerHTML = `<span>${r.nickname}</span> <button class="btn-confirm" onclick="window.confirm(${r.from_id})">Принять</button>`;
        listEl.appendChild(div);
        pendingElements[r.from_id] = div;
      }
    });
    Object.keys(pendingElements).forEach(id => {
      if (!currentIds.has(Number(id))) { pendingElements[id].remove(); delete pendingElements[id]; }
    });
  } catch (e) { console.error(e); }
};

window.confirm = async (id) => {
  await api('/api/contact/confirm', { method: 'POST', body: JSON.stringify({ from_id: id }) });
  if (pendingElements[id]) { pendingElements[id].remove(); delete pendingElements[id]; }
  loadPending(); loadDialogs();
};

const loadDialogs = async () => {
  try {
    const dialogs = await api('/api/dialogs');
    const container = document.getElementById('dialogs-list');
    const serverIds = new Set();
    
    dialogs.forEach(dialog => {
      serverIds.add(dialog.id);
      let item = dialogElements[dialog.id];
      if (!item) {
        const div = document.createElement('div');
        div.className = 'dialog-item';
        if (currentDialogId === dialog.id) div.classList.add('active');
        div.dataset.dialogId = dialog.id;
        div.innerHTML = `<div class="dialog-info">💬 <span>${dialog.nickname}</span></div><span class="unread-badge" style="display:none"></span>`;
        div.onclick = (evt) => window.selectDialog(dialog.id, dialog.nickname, dialog.other_id, evt);
        container.appendChild(div);
        dialogElements[dialog.id] = div;
      } else {
        if (currentDialogId === dialog.id) item.classList.add('active');
        else item.classList.remove('active');
      }
    });
    
    //  Удаляем диалоги, которых больше нет на сервере
    Object.keys(dialogElements).forEach(id => {
      if (!serverIds.has(Number(id))) {
        dialogElements[id].remove();
        delete dialogElements[id];
        delete unreadCounts[id];
        delete displayedMessageIds[id];
        
        //  Если удалили текущий диалог - закрываем его
        if (currentDialogId == id) {
          window.leaveChat();
        }
      }
    });
  } catch (e) { console.error('Load dialogs error:', e); }
};

window.selectDialog = async (id, name, otherId, evt) => {
  currentDialogId = id;
  currentDialogPartnerId = otherId;
  displayedMessageIds[id] = displayedMessageIds[id] || new Set();
  
  // ✅ Сбрасываем ключ
  currentPartnerJwk = null;
  
  document.getElementById('chat-header').classList.remove('hidden');
  document.getElementById('chat-title-text').textContent = name;
  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('messages').classList.remove('hidden');
  document.getElementById('chat-input-bar').classList.remove('hidden');
  
  document.getElementById('app-screen').classList.add('chat-active');
  
  const input = document.getElementById('msg-input');
  input.disabled = false;
  input.focus();
  document.getElementById('send-btn').disabled = false;

  unreadCounts[id] = 0;
  updateBadge(id, 0);
  
  try {
    const users = await api(`/api/users/search?q=${encodeURIComponent(name)}`);
    const partner = users.find(u => u.id === otherId);
    
    // ✅ ПРОВЕРКА: есть ли public_key
    if (!partner || !partner.public_key) {
      console.error('❌ Partner has no public key:', partner);
      document.getElementById('messages').innerHTML = `
        <div style="text-align:center;opacity:0.7;margin-top:30%;padding:20px;">
          <div style="font-size:48px;margin-bottom:15px;">⚠️</div>
          <h3>Пользователь не активен</h3>
          <p>${name} не вошёл в систему или не сгенерировал ключи.<br>
          Сообщения не могут быть зашифрованы.</p>
        </div>
      `;
      document.getElementById('chat-input-bar').classList.add('hidden');
      return;
    }
    
    currentPartnerJwk = partner.public_key;
    console.log('✅ Partner key loaded');
  } catch (e) { 
    console.error(e); 
    document.getElementById('messages').innerHTML = 
      '<div style="text-align:center;opacity:0.5;margin-top:20%">Ошибка загрузки</div>';
    return;
  }
  
  await loadAllMessages();
  Object.values(dialogElements).forEach(el => el.classList.remove('active'));
  if (dialogElements[id]) dialogElements[id].classList.add('active');
};

window.leaveChat = () => {
  currentDialogId = null;
  currentDialogPartnerId = null;
  
  //  Скрываем шапку диалога
  document.getElementById('chat-header').classList.add('hidden');
  document.getElementById('empty-state').classList.remove('hidden');
  document.getElementById('messages').classList.add('hidden');
  document.getElementById('chat-input-bar').classList.add('hidden');
  
  //  Мобильный переход
  document.getElementById('app-screen').classList.remove('chat-active');
  
  document.getElementById('msg-input').disabled = true;
  document.getElementById('send-btn').disabled = true;
  document.getElementById('msg-input').value = '';
  
  Object.values(dialogElements).forEach(el => el.classList.remove('active'));
};

const loadAllMessages = async () => {
  if (!currentDialogId || !currentPartnerJwk) return;
  
  try {
    const msgs = await api(`/api/messages/${currentDialogId}`);
    const aesKey = await deriveKey(currentPartnerJwk);
    const container = document.getElementById('messages');
    
    const scrollHeight = container.scrollHeight;
    const scrollTop = container.scrollTop;
    
    container.innerHTML = '';
    displayedMessageIds[currentDialogId] = new Set();
    newMessageCount = 0;
    window.showNewMsgBadge(0);
    isAtBottom = true;
    
    for (const m of msgs) {
      if (displayedMessageIds[currentDialogId].has(m.id)) continue;
      
      try {
        const pt = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: unb64(m.iv_base64) }, 
          aesKey, 
          unb64(m.content_base64)
        );
        const text = new TextDecoder().decode(pt);
        const isMe = m.sender_id === currentUser.id;
        
        const div = document.createElement('div');
        div.className = `message ${isMe ? 'msg-sent' : 'msg-recv'}`;
        div.innerHTML = `
          <div class="message-text">${text}</div>
          <div class="message-time">${formatMessageTime(m.created_at)}</div>
        `;
        container.appendChild(div);
      } catch (e) {
        // ⛔ Молча пропускаем, старые ключи не восстановить
      }
      
      // ✅ ОБЯЗАТЕЛЬНО помечаем как обработанное, даже если декрипт не прошёл
      displayedMessageIds[currentDialogId].add(m.id);
    }
    
    if (msgs.length > 0) {
      lastReadMessageId[String(currentDialogId)] = msgs[msgs.length - 1].id;
      localStorage.setItem('lastReadMessages', JSON.stringify(lastReadMessageId));
    }
    
    setTimeout(() => {
      container.scrollTop = container.scrollHeight;
      checkScrollPosition();
    }, 50);
  } catch (e) {
    console.error('❌ loadAllMessages error:', e);
  }
};

const loadNewMessages = async () => {
  if (!currentDialogId || !currentPartnerJwk) return;
  
  try {
    const msgs = await api(`/api/messages/${currentDialogId}`);
    const aesKey = await deriveKey(currentPartnerJwk);
    const container = document.getElementById('messages');
    
    if (msgs.length === 0) {
      container.innerHTML = '';
      displayedMessageIds[currentDialogId].clear();
      return;
    }
    
    let newCount = 0;
    
    for (const m of msgs) {
      if (displayedMessageIds[currentDialogId].has(m.id)) continue;
      
      try {
        const pt = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: unb64(m.iv_base64) }, 
          aesKey, 
          unb64(m.content_base64)
        );
        const text = new TextDecoder().decode(pt);
        const isMe = m.sender_id === currentUser.id;
        
        const optimisticMsg = Array.from(container.querySelectorAll('.message.msg-sent[data-local="true"]'))
          .find(msg => msg.dataset.tempText === text);
        
        if (optimisticMsg) {
          optimisticMsg.innerHTML = `
            <div class="message-text">${text}</div>
            <div class="message-time">${formatMessageTime(m.created_at)}</div>
          `;
          delete optimisticMsg.dataset.local;
          delete optimisticMsg.dataset.tempText;
        } else {
          const div = document.createElement('div');
          div.className = `message ${isMe ? 'msg-sent' : 'msg-recv'}`;
          div.innerHTML = `
            <div class="message-text">${text}</div>
            <div class="message-time">${formatMessageTime(m.created_at)}</div>
          `;
          container.appendChild(div);
        }
        
        if (!isMe) newCount++;
      } catch (e) {
        // ⛔ Старые сообщения на старом ключе не декриптнутся. Пропускаем.
      }
      
      // ✅ Помечаем ID, чтобы опрос не долбил это сообщение каждые 3 секунды
      displayedMessageIds[currentDialogId].add(m.id);
    }
    
    if (newCount > 0 && !isAtBottom) {
      newMessageCount += newCount;
      window.showNewMsgBadge(newMessageCount);
    } else if (isAtBottom) {
      container.scrollTop = container.scrollHeight;
    }
    
    if (msgs.length > 0) {
      lastReadMessageId[String(currentDialogId)] = msgs[msgs.length - 1].id;
      localStorage.setItem('lastReadMessages', JSON.stringify(lastReadMessageId));
    }
  } catch (e) {
    if (e.message && e.message.includes('Not in dialog')) {
      window.leaveChat();
      loadDialogs();
    } else {
      console.error('❌ loadNewMessages error:', e);
    }
  }
};

//  ОБРАБОТКА СКРОЛЛА ВВЕРХ
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('messages');
  if (container) {
    container.addEventListener('scroll', () => {
      if (container.scrollTop === 0 && currentDialogId) {
        isScrollingUp = true;
        // Здесь можно добавить загрузку старых сообщений
      }
    });
  }
});

window.toggleMenu = () => {
  document.getElementById('side-menu').classList.add('active');
  document.getElementById('overlay').classList.add('active');
};

window.closeMenu = () => {
  document.getElementById('side-menu').classList.remove('active');
  document.getElementById('overlay').classList.remove('active');
};

window.clearMessages = async () => {
  if (!currentDialogId) return;
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `<div class="modal-box"><h3>Очистить диалог?</h3><p>Сообщения удалятся без возможности восстановления!</p><div class="modal-buttons"><button class="btn-confirm" id="confirm-clear">Да</button><button class="btn-cancel" id="cancel-clear">Нет</button></div></div>`;
  document.body.appendChild(modal);
  document.getElementById('cancel-clear').onclick = () => modal.remove();
  document.getElementById('confirm-clear').onclick = async () => {
    try {
      await api(`/api/dialogs/${currentDialogId}`, { method: 'DELETE' });
      document.getElementById('messages').innerHTML = '';
      displayedMessageIds[currentDialogId].clear();
      unreadCounts[currentDialogId] = 0; updateBadge(currentDialogId, 0);
      modal.remove();
    } catch (e) { alert(e.message); modal.remove(); }
  };
  modal.onclick = e => { if(e.target===modal) modal.remove(); };
};

window.removeFriend = async () => {
  if (!currentDialogId || !currentDialogPartnerId) return;
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `<div class="modal-box"><h3>Удалить из друзей?</h3><p>Пользователь будет удален из друзей, сообщения будут удалены безвозвратно!</p><div class="modal-buttons"><button class="btn-confirm" id="confirm-remove">Да</button><button class="btn-cancel" id="cancel-remove">Нет</button></div></div>`;
  document.body.appendChild(modal);
  document.getElementById('cancel-remove').onclick = () => modal.remove();
  document.getElementById('confirm-remove').onclick = async () => {
    try {
      await api(`/api/contacts/${currentDialogPartnerId}`, { method: 'DELETE' });
      if(dialogElements[currentDialogId]) { dialogElements[currentDialogId].remove(); delete dialogElements[currentDialogId]; }
      delete unreadCounts[currentDialogId]; delete displayedMessageIds[currentDialogId]; delete lastReadMessageId[String(currentDialogId)];
      window.leaveChat(); modal.remove(); loadDialogs();
    } catch (e) { alert(e.message); modal.remove(); }
  };
  modal.onclick = e => { if(e.target===modal) modal.remove(); };
};

window.logout = () => {
  localStorage.removeItem('auth_token'); localStorage.removeItem('user');
  localStorage.removeItem('lastReadMessages'); localStorage.removeItem('unreadCounts');
  authToken = null; currentUser = {}; myPrivateKey = null;
  currentDialogId = null; currentDialogPartnerId = null; currentPartnerJwk = null;
  dialogElements = {}; pendingElements = {}; displayedMessageIds = {}; unreadCounts = {}; lastReadMessageId = {};
  document.getElementById('dialogs-list').innerHTML = '';
  document.getElementById('pending-list').innerHTML = '';
  document.getElementById('messages').innerHTML = '';
  if(pollTimer) clearInterval(pollTimer);
  window.closeMenu();
  window.leaveChat();
  document.getElementById('app-screen').classList.add('hidden');
  document.getElementById('auth-screen').classList.remove('hidden');
  document.getElementById('nickname').value = '';
  document.getElementById('password').value = '';
  document.getElementById('auth-msg').textContent = '';
};

window.sendMessage = async () => {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !currentDialogId || !currentPartnerJwk) return;
  input.value = '';
  
  //  Показываем сообщение СРАЗУ с локальным временем
  const container = document.getElementById('messages');
  const now = new Date();
  const localTime = now.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  
  const div = document.createElement('div');
  div.className = 'message msg-sent';
  div.innerHTML = `
    <div class="message-text">${text}</div>
    <div class="message-time">${localTime}</div>
  `;
  div.dataset.local = 'true';
  div.dataset.tempText = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  
  try {
    const aesKey = await deriveKey(currentPartnerJwk);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(text));
    
    await api('/api/messages', { method: 'POST', body: JSON.stringify({ dialog_id: currentDialogId, content_base64: b64(ct), iv_base64: b64(iv) }) });
    
    //  Не заменяем сообщение — время уже показано правильно
    // Просто помечаем как отправленное
    displayedMessageIds[currentDialogId].add(Date.now()); // Временный ID
    
  } catch (e) {
    if (e.message && e.message.includes('Not in dialog')) { 
      alert('Диалог удален'); 
      window.leaveChat(); 
      loadDialogs(); 
    } else { 
      console.error(e); 
      const c = document.getElementById('messages'); 
      const l = c.lastElementChild; 
      if(l && l.dataset.local === 'true') l.remove(); 
      input.value = text; 
    }
  }
};

if (authToken && currentUser.id) startApp();