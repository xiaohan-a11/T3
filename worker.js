class RSACrypto {
  constructor() {
    this.n = BigInt('0xca5d41f38935dbb009b9cc2a204f4c4f80e290a63f98762c8a48a26d10efaa3ead423806b589e29ac20dc7d24205d02f5753aa6c19ea5c7c2902626ead6b3931327c414297c0ce2f2e821816da1be48fdd8457d317498f458800b897a72210f4935dc4dde84116939ea18372650efbbd1c2789c54cd4fea3411dff3f01212102');
    this.e = BigInt('0x10001');
    this.keySize = 128;
  }
  async encryptToHex(data) {
    const dataBuffer = new TextEncoder().encode(data);
    const encrypted = await crypto.subtle.encrypt({ name: 'RSAES-PKCS1-V1_5' }, await this._getPublicKey(), dataBuffer);
    const hashArray = Array.from(new Uint8Array(encrypted));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  async _getPublicKey() {
    const hexToBytes = (hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      return bytes;
    };
    const bytesToBase64Url = (bytes) => {
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const jwk = { kty: 'RSA', n: bytesToBase64Url(hexToBytes(this.n.toString(16))), e: 'AQAB', alg: 'RSA-OAEP-256', ext: true };
    return await crypto.subtle.importKey('jwk', jwk, { name: 'RSAES-PKCS1-V1_5' }, false, ['encrypt']);
  }
  _modPow(base, exp, mod) {
    let result = 1n; base = base % mod;
    while (exp > 0n) { if (exp % 2n === 1n) result = (result * base) % mod; exp = exp >> 1n; base = (base * base) % mod; }
    return result;
  }
  _bufferToBigInt(buffer) {
    let result = 0n;
    for (let i = 0; i < buffer.length; i++) result = (result << 8n) | BigInt(buffer[i]);
    return result;
  }
  _bigIntToBuffer(bigint, length) {
    const hex = bigint.toString(16).padStart(length * 2, '0');
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
  }
  decryptFromBase64(base64Str) {
    const binaryStr = atob(base64Str);
    const encryptedData = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) encryptedData[i] = binaryStr.charCodeAt(i);
    const decryptedBlocks = []; let offset = 0;
    while (offset < encryptedData.length) {
      const block = encryptedData.slice(offset, offset + this.keySize);
      let blockInt = this._bufferToBigInt(block);
      let decryptedInt = this._modPow(blockInt, this.e, this.n);
      let decryptedBlock = this._bigIntToBuffer(decryptedInt, this.keySize);
      let padEnd = -1;
      for (let i = 2; i < decryptedBlock.length; i++) { if (decryptedBlock[i] === 0x00) { padEnd = i; break; } }
      decryptedBlocks.push(padEnd !== -1 ? decryptedBlock.slice(padEnd + 1) : decryptedBlock);
      offset += this.keySize;
    }
    let totalLength = 0;
    for (const b of decryptedBlocks) totalLength += b.length;
    const result = new Uint8Array(totalLength); let pos = 0;
    for (const b of decryptedBlocks) { result.set(b, pos); pos += b.length; }
    return new TextDecoder().decode(result);
  }
}class T3Verify {
  constructor(env) {
    this.serverUrls = ['https://w.t3yanzheng.com/', 'https://w2.t3yanzheng.com/', 'https://w3.t3yanzheng.com/', 'https://w4.t3yanzheng.com/', 'https://w5.t3yanzheng.com/', 'https://w.t3data.net/'];
    this.serverUrl = this.serverUrls[0];
    this.env = env;
    this.unbindCode = env.T3_UNBIND_CODE;
    this.appkey = env.T3_APPKEY;
    this.rsaCrypto = new RSACrypto();
  }
  _buildUrl(code) {
    return this.serverUrl.endsWith('/') ? `${this.serverUrl}${code}` : `${this.serverUrl}/${code}`;
  }
  async _encodeParams(params) {
    const encodedParams = {};
    for (const key of Object.keys(params)) encodedParams[key] = await this.rsaCrypto.encryptToHex(String(params[key]));
    const parts = Object.keys(params).map(key => `${key}=${encodedParams[key]}`);
    const sString = parts.join('&') + '&' + this.appkey;
    encodedParams['s'] = await this.rsaCrypto.encryptToHex(await this._md5(sString));
    return new URLSearchParams(encodedParams).toString();
  }
  async _md5(str) {
    const msgBuffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('MD5', msgBuffer);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
  }
  async _decodeResponse(responseText) {
    return JSON.parse(this.rsaCrypto.decryptFromBase64(responseText));
  }
  async _httpRequest(url, postData) {
    for (const server of this.serverUrls) {
      try {
        const targetUrl = new URL(url.replace(this.serverUrl, server));
        const res = await fetch(targetUrl.toString(), { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: postData });
        if (res.status === 200) { this.serverUrl = server; return await res.text(); }
      } catch (e) { }
    }
    throw new Error('无法连接到所有T3服务器');
  }
  async queryKami(kami) {
    try {
      const url = this._buildUrl(this.env.T3_QUERY_CODE);
      const postData = await this._encodeParams({ kami: kami, t: Math.floor(Date.now() / 1000) });
      const jsonData = await this._decodeResponse(await this._httpRequest(url, postData));
      if (jsonData.code !== 200) return { success: false, error: jsonData.msg || '未知错误' };
      return { success: true, state: jsonData.state, use: jsonData.use, id: jsonData.id, use_time: jsonData.use_time, end_time: jsonData.end_time, line_time: jsonData.line_time, line: jsonData.line, amount: jsonData.amount, available: jsonData.available };
    } catch (e) { return { success: false, error: e.message }; }
  }
  async unbindKami(kami, imei) {
    try {
      const url = this._buildUrl(this.unbindCode);
      const postData = await this._encodeParams({ kami: kami, imei: imei, t: Math.floor(Date.now() / 1000) });
      const jsonData = await this._decodeResponse(await this._httpRequest(url, postData));
      if (jsonData.code !== 200) return { success: false, error: jsonData.msg || '未知错误' };
      return { success: true, msg: jsonData.msg || '解绑成功' };
    } catch (e) { return { success: false, error: e.message }; }
  }
}async function sendMessage(env, chatId, text, replyMarkup = null, replyToMessageId = null) {
  const body = { chat_id: chatId, text: text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (replyMarkup) body.reply_markup = JSON.stringify(replyMarkup);
  if (replyToMessageId) body.reply_to_message_id = replyToMessageId;
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
async function editMessage(env, chatId, messageId, text, replyMarkup = null) {
  const body = { chat_id: chatId, message_id: messageId, text: text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (replyMarkup) body.reply_markup = JSON.stringify(replyMarkup);
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
async function answerCallbackQuery(env, callbackQueryId) {
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/answerCallbackQuery`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ callback_query_id: callbackQueryId }) });
}
function getMainKeyboard() {
  return { inline_keyboard: [ [{ text: '查询卡密', callback_data: 'query_card' }, { text: '我的卡密', callback_data: 'my_cards' }], [{ text: '解绑卡密', callback_data: 'unbind_card_menu' }, { text: '解绑TG', callback_data: 'unbind_tg_menu' }] ] };
}export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/registerWebhook') {
      const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setWebhook?url=${encodeURIComponent(`${url.origin}/webhook`)}`);
      return new Response(`<h1>Webhook注册结果</h1><pre>${JSON.stringify(await res.json(), null, 2)}</pre>`, { headers: { 'Content-Type': 'text/html' } });
    }
    if (url.pathname === '/webhook' && request.method === 'POST') {
      try {
        const update = await request.json();
        const t3 = new T3Verify(env);
        if (update.message && update.message.text) {
          const chatId = update.message.chat.id;
          const text = update.message.text.trim();
          const uid = chatId.toString();
          if (text === '/start') { await sendMessage(env, chatId, `请选择以下操作`, getMainKeyboard()); }
          else {
            const cardData = await t3.queryKami(text);
            if (!cardData.success) { await sendMessage(env, chatId, `未查询到卡密\n\n请点击下方按钮返回`, { inline_keyboard: [[{ text: '返回', callback_data: 'back_to_start' }]] }); return new Response('OK', { status: 200 }); }
            const replyText = `——卡密查询结果——\n卡密   ${text}\n状态   ${cardData.use || '未知'}\n时长   ${cardData.amount || '未知'}\n激活时间   ${cardData.use_time || '未激活'}\n到期时间   ${cardData.end_time || '未激活'}`;
            await sendMessage(env, chatId, replyText, { inline_keyboard: [[{ text: '绑定卡密', callback_data: `bind_${text}` }, { text: '解绑卡密', callback_data: `unbind_${text}` }], [{ text: '返回主页面', callback_data: 'back_to_start' }]] });
          }
        }if (update.callback_query) {
  const callbackQuery = update.callback_query;
  const chatId = callbackQuery.message.chat.id;
  const messageId = callbackQuery.message.message_id;
  const data = callbackQuery.data;
  const uid = chatId.toString();
  await answerCallbackQuery(env, callbackQuery.id);
  if (data === 'back_to_start') { await editMessage(env, chatId, messageId, `请选择以下操作`, getMainKeyboard()); }
  else if (data === 'query_card') { await editMessage(env, chatId, messageId, `请发送你要查询的卡密`, { inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]] }); }
  else if (data.startsWith('bind_')) {
    const card = data.replace('bind_', '');
    const existingBind = await env.T3_KV.get(`card_${card}`);
    if (existingBind && existingBind !== uid) { await sendMessage(env, chatId, `该卡密已被其他TG账号绑定，无法重复绑定。`); return new Response('OK', { status: 200 }); }
    await env.T3_KV.put(`card_${card}`, uid);
    let userCards = await env.T3_KV.get(`user_${uid}`);
    userCards = userCards ? JSON.parse(userCards) : [];
    if (!userCards.includes(card)) { userCards.push(card); await env.T3_KV.put(`user_${uid}`, JSON.stringify(userCards)); }
    await sendMessage(env, chatId, `✅ 绑定成功！\n卡密：${card}\n\n现在您可以使用此卡密进行解绑操作。`);
  }
  else if (data.startsWith('unbind_') && !data.includes('_menu')) {
    const card = data.replace('unbind_', '');
    const boundUid = await env.T3_KV.get(`card_${card}`);
    if (!boundUid) { await sendMessage(env, chatId, `该卡密尚未被绑定，无需解绑。`); return new Response('OK', { status: 200 }); }
    if (boundUid !== uid) { await sendMessage(env, chatId, `tguid错误，无法解绑他人卡密`); return new Response('OK', { status: 200 }); }
    await t3.unbindKami(card, 'TG_BOT_UNBIND');
    await env.T3_KV.delete(`card_${card}`);
    let userCards = await env.T3_KV.get(`user_${uid}`);
    if (userCards) { userCards = JSON.parse(userCards).filter(c => c !== card); await env.T3_KV.put(`user_${uid}`, JSON.stringify(userCards)); }
    await sendMessage(env, chatId, `您的卡密(${card})已成功解绑`);
  }          else if (data === 'my_cards') {
            let userCards = await env.T3_KV.get(`user_${uid}`);
            userCards = userCards ? JSON.parse(userCards) : [];
            if (userCards.length === 0) { await editMessage(env, chatId, messageId, `您还没有绑定任何卡密。`, { inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]] }); }
            else {
              let msg = `您的卡密有\n\n`; userCards.forEach(card => { msg += `${card}\n`; });
              await editMessage(env, chatId, messageId, msg, { inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]] });
            }
          }
          else if (data === 'unbind_tg_menu') {
            let userCards = await env.T3_KV.get(`user_${uid}`);
            userCards = userCards ? JSON.parse(userCards) : [];
            if (userCards.length === 0) { await editMessage(env, chatId, messageId, `您还没有绑定任何卡密。`, { inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]] }); }
            else {
              const buttons = userCards.map(card => [{ text: card, callback_data: `confirm_unbind_tg_${card}` }]);
              buttons.push([{ text: '返回主页面', callback_data: 'back_to_start' }]);
              await editMessage(env, chatId, messageId, `请选择需要解绑tg的卡密`, { inline_keyboard: buttons });
            }
          }
          else if (data.startsWith('confirm_unbind_tg_')) {
            const card = data.replace('confirm_unbind_tg_', '');
            await editMessage(env, chatId, messageId, `确认是否将该卡密(${card})`, { inline_keyboard: [[{ text: '确认解绑', callback_data: `do_unbind_tg_${card}` }, { text: '取消解绑', callback_data: 'back_to_start' }]] });
          }
          else if (data.startsWith('do_unbind_tg_')) {
            const card = data.replace('do_unbind_tg_', '');
            if (await env.T3_KV.get(`card_${card}`) === uid) {
              await env.T3_KV.delete(`card_${card}`);
              let userCards = await env.T3_KV.get(`user_${uid}`);
              if (userCards) { userCards = JSON.parse(userCards).filter(c => c !== card); await env.T3_KV.put(`user_${uid}`, JSON.stringify(userCards)); }
              await editMessage(env, chatId, messageId, `已成功解绑该卡密与您的TG账号，其他账号现在可以绑定了。`, { inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]] });
            } else {
              await editMessage(env, chatId, messageId, `tguid错误，无法解绑他人卡密`, { inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]] });
            }
          }
        }
        return new Response('OK', { status: 200 });
      } catch (err) { console.error(err); return new Response('Error: ' + err.message, { status: 500 }); }
    }
    return new Response(`<h1>T3卡密查询机器人</h1><p>状态：<b>运行中</b></p>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};