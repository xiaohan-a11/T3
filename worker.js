// ==========================================
// T3 网络验证 Telegram 机器人 - 修正版
// 功能：查询卡密、绑定卡密、解绑卡密、解绑TG
// ==========================================

class CustomBase64 {
  constructor(customCharset) {
    this.standardCharset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    this.customCharset = customCharset;
  }
  encodeToHex(data) {
    const buffer = new TextEncoder().encode(data);
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    const standardB64 = btoa(binary);
    let customB64 = '';
    for (let i = 0; i < standardB64.length; i++) {
      const char = standardB64[i];
      const index = this.standardCharset.indexOf(char);
      customB64 += index !== -1 ? this.customCharset[index] : char;
    }
    const hex = Array.from(new TextEncoder().encode(customB64)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex.toUpperCase();
  }
}

class RSACrypto {
  constructor(publicKeyPem) {
    this.publicKeyPem = publicKeyPem.trim();
    this.n = null;
    this.e = null;
    this.keySize = 0;
    this._parsePublicKey();
  }

  _parsePublicKey() {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    let pemContents = this.publicKeyPem;
    if (pemContents.includes(pemHeader)) {
      pemContents = pemContents.substring(pemHeader.length, pemContents.length - pemFooter.length).replace(/\s/g, '');
    }
    const binaryDerString = atob(pemContents);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) binaryDer[i] = binaryDerString.charCodeAt(i);

    let offset = 0;
    const readTag = () => binaryDer[offset++];
    const readLength = () => {
      let length = binaryDer[offset++];
      if (length & 0x80) {
        const numBytes = length & 0x7f;
        length = 0;
        for (let i = 0; i < numBytes; i++) length = (length << 8) | binaryDer[offset++];
      }
      return length;
    };
    const readInteger = () => {
      const tag = readTag();
      if (tag !== 0x02) throw new Error('Expected INTEGER tag');
      const len = readLength();
      const bytes = binaryDer.slice(offset, offset + len);
      offset += len;
      let value = 0n;
      for (let i = 0; i < bytes.length; i++) value = (value << 8n) | BigInt(bytes[i]);
      return value;
    };

    readTag(); readLength();
    this.n = readInteger();
    this.e = readInteger();
    this.keySize = Math.ceil(this.n.toString(16).length / 2);
  }

  async encryptToHex(data) {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    let pemContents = this.publicKeyPem;
    if (pemContents.includes(pemHeader)) {
      pemContents = pemContents.substring(pemHeader.length, pemContents.length - pemFooter.length).replace(/\s/g, '');
    }
    const binaryDerString = atob(pemContents);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) binaryDer[i] = binaryDerString.charCodeAt(i);
    
    const key = await crypto.subtle.importKey(
      'spki', binaryDer.buffer, { name: 'RSAES-PKCS1-V1_5' }, false, ['encrypt']
    );
    const dataBuffer = new TextEncoder().encode(data);
    const encrypted = await crypto.subtle.encrypt({ name: 'RSAES-PKCS1-V1_5' }, key, dataBuffer);
    const hashArray = Array.from(new Uint8Array(encrypted));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  _modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = (result * base) % mod;
      exp = exp >> 1n;
      base = (base * base) % mod;
    }
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

    const decryptedBlocks = [];
    let offset = 0;
    while (offset < encryptedData.length) {
      const block = encryptedData.slice(offset, offset + this.keySize);
      let blockInt = this._bufferToBigInt(block);
      let decryptedInt = this._modPow(blockInt, this.e, this.n);
      let decryptedBlock = this._bigIntToBuffer(decryptedInt, this.keySize);
      
      let padEnd = -1;
      for (let i = 2; i < decryptedBlock.length; i++) {
        if (decryptedBlock[i] === 0x00) { padEnd = i; break; }
      }
      if (padEnd !== -1) {
        decryptedBlocks.push(decryptedBlock.slice(padEnd + 1));
      } else {
        decryptedBlocks.push(decryptedBlock);
      }
      offset += this.keySize;
    }

    let totalLength = 0;
    for (const b of decryptedBlocks) totalLength += b.length;
    const result = new Uint8Array(totalLength);
    let pos = 0;
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
    this.encodeType = 'rsa';
    this.rsaCrypto = new RSACrypto(env.T3_RSA_PUBLIC_KEY);
  }

  _buildUrl(code) {
    return this.serverUrl.endsWith('/') ? `${this.serverUrl}${code}` : `${this.serverUrl}/${code}`;
  }

  async _encodeParams(params) {
    const encodedParams = {};
    for (const key of Object.keys(params)) {
      encodedParams[key] = await this.rsaCrypto.encryptToHex(String(params[key]));
    }
    const parts = Object.keys(params).map(key => `${key}=${encodedParams[key]}`);
    const sString = parts.join('&') + '&' + this.appkey;
    const sValue = await this._md5(sString);
    encodedParams['s'] = await this.rsaCrypto.encryptToHex(sValue);
    return new URLSearchParams(encodedParams).toString();
  }

  async _md5(str) {
    const msgBuffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('MD5', msgBuffer);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
  }

  async _decodeResponse(responseText) {
    try {
      const decrypted = this.rsaCrypto.decryptFromBase64(responseText);
      return JSON.parse(decrypted);
    } catch (e) {
      throw new Error(`响应解码失败: ${e.message}`);
    }
  }

  async _httpRequest(url, postData) {
    for (const server of this.serverUrls) {
      try {
        const targetUrl = new URL(url.replace(this.serverUrl, server));
        const res = await fetch(targetUrl.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: postData
        });
        if (res.status === 200) {
          const text = await res.text();
          this.serverUrl = server;
          return text;
        }
      } catch (e) { }
    }
    throw new Error('无法连接到所有T3网络验证服务器');
  }

  async queryKami(kami) {
    try {
      const url = this._buildUrl(this.env.T3_QUERY_CODE);
      const params = { kami: kami, t: Math.floor(Date.now() / 1000) };
      const postData = await this._encodeParams(params);
      const responseText = await this._httpRequest(url, postData);
      const jsonData = await this._decodeResponse(responseText);
      if (jsonData.code !== 200) return { success: false, error: jsonData.msg || '未知错误' };
      return {
        success: true, state: jsonData.state, use: jsonData.use,
        id: jsonData.id, use_time: jsonData.use_time,
        end_time: jsonData.end_time, line_time: jsonData.line_time,
        line: jsonData.line, amount: jsonData.amount,
        available: jsonData.available
      };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async unbindKami(kami, imei) {
    try {
      const url = this._buildUrl(this.unbindCode);
      const params = { kami: kami, imei: imei, t: Math.floor(Date.now() / 1000) };
      const postData = await this._encodeParams(params);
      const responseText = await this._httpRequest(url, postData);
      const jsonData = await this._decodeResponse(responseText);
      if (jsonData.code !== 200) return { success: false, error: jsonData.msg || '未知错误' };
      return { success: true, msg: jsonData.msg || '解绑成功' };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
}async function sendMessage(env, chatId, text, replyMarkup = null, replyToMessageId = null) {
  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`;
  const body = { chat_id: chatId, text: text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (replyMarkup) body.reply_markup = JSON.stringify(replyMarkup);
  if (replyToMessageId) body.reply_to_message_id = replyToMessageId;
  
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errText = await res.text();
    console.error(`Telegram API 错误 (sendMessage): ${res.status} - ${errText}`);
  }
}

async function editMessage(env, chatId, messageId, text, replyMarkup = null) {
  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`;
  const body = { chat_id: chatId, message_id: messageId, text: text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (replyMarkup) body.reply_markup = JSON.stringify(replyMarkup);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errText = await res.text();
    console.error(`Telegram API 错误 (editMessage): ${res.status} - ${errText}`);
  }
}

async function answerCallbackQuery(env, callbackQueryId, text = '') {
  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/answerCallbackQuery`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query_id: callbackQueryId, text: text }),
  });
}function getMainKeyboard() {
  return {
    inline_keyboard: [
      [{ text: '查询卡密', callback_data: 'query_card' }, { text: '我的卡密', callback_data: 'my_cards' }],
      [{ text: '解绑卡密', callback_data: 'unbind_card_menu' }, { text: '解绑TG', callback_data: 'unbind_tg_menu' }]
    ]
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/registerWebhook') {
      const webhookUrl = `${url.origin}/webhook`;
      const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`);
      const data = await res.json();
      return new Response(`<h1>Webhook注册结果</h1><pre>${JSON.stringify(data, null, 2)}</pre>`, { headers: { 'Content-Type': 'text/html' } });
    }

    if (url.pathname === '/webhook' && request.method === 'POST') {
      try {
        const update = await request.json();
        const t3 = new T3Verify(env);

        if (update.message && update.message.text) {
          const chatId = update.message.chat.id;
          const text = update.message.text.trim();
          const messageId = update.message.message_id;
          const uid = chatId.toString();

          if (text === '/start') {
            await sendMessage(env, chatId, `请选择以下操作`, getMainKeyboard());
          } else {
            const cardData = await t3.queryKami(text);
            if (!cardData.success) {
              await sendMessage(env, chatId, `未查询到卡密\n\n请点击下方按钮返回`, {
                inline_keyboard: [[{ text: '返回', callback_data: 'back_to_start' }]]
              });
              return new Response('OK', { status: 200 });
            }
            const replyText = `——卡密查询结果——\n卡密   ${text}\n状态   ${cardData.use || '未知'}\n时长   ${cardData.amount || '未知'}\n激活时间   ${cardData.use_time || '未激活'}\n到期时间   ${cardData.end_time || '未激活'}`;
            const keyboard = {
              inline_keyboard: [
                [{ text: '绑定卡密', callback_data: `bind_${text}` }, { text: '解绑卡密', callback_data: `unbind_${text}` }],
                [{ text: '返回主页面', callback_data: 'back_to_start' }]
              ]
            };
            await sendMessage(env, chatId, replyText, keyboard);
          }
        }        if (update.callback_query) {
          const callbackQuery = update.callback_query;
          const chatId = callbackQuery.message.chat.id;
          const messageId = callbackQuery.message.message_id;
          const data = callbackQuery.data;
          const uid = chatId.toString();

          await answerCallbackQuery(env, callbackQuery.id);

          if (data === 'back_to_start') {
            await editMessage(env, chatId, messageId, `请选择以下操作`, getMainKeyboard());
          }
          else if (data === 'query_card') {
            await editMessage(env, chatId, messageId, `请发送你要查询的卡密`, {
              inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]]
            });
          }
          else if (data.startsWith('bind_')) {
            const card = data.replace('bind_', '');
            const existingBind = await env.T3_KV.get(`card_${card}`);
            if (existingBind && existingBind !== uid) {
              await sendMessage(env, chatId, `该卡密已被其他TG账号绑定，无法重复绑定。`);
              return new Response('OK', { status: 200 });
            }
            await env.T3_KV.put(`card_${card}`, uid);
            let userCards = await env.T3_KV.get(`user_${uid}`);
            userCards = userCards ? JSON.parse(userCards) : [];
            if (!userCards.includes(card)) {
              userCards.push(card);
              await env.T3_KV.put(`user_${uid}`, JSON.stringify(userCards));
            }
            await sendMessage(env, chatId, `✅ 绑定成功！\n卡密：${card}\n\n现在您可以使用此卡密进行解绑操作。`);
          }
          else if (data.startsWith('unbind_') && !data.includes('_menu')) {
            const card = data.replace('unbind_', '');
            const boundUid = await env.T3_KV.get(`card_${card}`);
            if (!boundUid) {
              await sendMessage(env, chatId, `该卡密尚未被绑定，无需解绑。`);
              return new Response('OK', { status: 200 });
            }
            if (boundUid !== uid) {
              await sendMessage(env, chatId, `tguid错误，无法解绑他人卡密`);
              return new Response('OK', { status: 200 });
            }
            const t3UnbindResult = await t3.unbindKami(card, 'TG_BOT_UNBIND');
            await env.T3_KV.delete(`card_${card}`);
            let userCards = await env.T3_KV.get(`user_${uid}`);
            if (userCards) {
              userCards = JSON.parse(userCards).filter(c => c !== card);
              await env.T3_KV.put(`user_${uid}`, JSON.stringify(userCards));
            }
            await sendMessage(env, chatId, `您的卡密(${card})已成功解绑`);
          }
          else if (data === 'my_cards') {
            const userCardsStr = await env.T3_KV.get(`user_${uid}`);
            const userCards = userCardsStr ? JSON.parse(userCardsStr) : [];
            if (userCards.length === 0) {
              await editMessage(env, chatId, messageId, `您还没有绑定任何卡密。`, {
                inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]]
              });
            } else {
              let msg = `您的卡密有\n\n`;
              userCards.forEach(card => { msg += `${card}\n`; });
              await editMessage(env, chatId, messageId, msg, {
                inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]]
              });
            }
          }
          else if (data === 'unbind_tg_menu') {
            const userCardsStr = await env.T3_KV.get(`user_${uid}`);
            const userCards = userCardsStr ? JSON.parse(userCardsStr) : [];
            if (userCards.length === 0) {
              await editMessage(env, chatId, messageId, `您还没有绑定任何卡密。`, {
                inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]]
              });
            } else {
              const buttons = userCards.map(card => [{ text: card, callback_data: `confirm_unbind_tg_${card}` }]);
              buttons.push([{ text: '返回主页面', callback_data: 'back_to_start' }]);
              await editMessage(env, chatId, messageId, `请选择需要解绑tg的卡密`, { inline_keyboard: buttons });
            }
          }
          else if (data.startsWith('confirm_unbind_tg_')) {
            const card = data.replace('confirm_unbind_tg_', '');
            const keyboard = {
              inline_keyboard: [
                [{ text: '确认解绑', callback_data: `do_unbind_tg_${card}` }, { text: '取消解绑', callback_data: 'back_to_start' }],
              ]
            };
            await editMessage(env, chatId, messageId, `确认是否将该卡密(${card})`, keyboard);
          }
          else if (data.startsWith('do_unbind_tg_')) {
            const card = data.replace('do_unbind_tg_', '');
            const boundUid = await env.T3_KV.get(`card_${card}`);
            if (boundUid === uid) {
              await env.T3_KV.delete(`card_${card}`);
              let userCards = await env.T3_KV.get(`user_${uid}`);
              if (userCards) {
                userCards = JSON.parse(userCards).filter(c => c !== card);
                await env.T3_KV.put(`user_${uid}`, JSON.stringify(userCards));
              }
              await editMessage(env, chatId, messageId, `已成功解绑该卡密与您的TG账号，其他账号现在可以绑定了。`, {
                inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]]
              });
            } else {
              await editMessage(env, chatId, messageId, `tguid错误，无法解绑他人卡密`, {
                inline_keyboard: [[{ text: '返回主页面', callback_data: 'back_to_start' }]]
              });
            }
          }
        }

        return new Response('OK', { status: 200 });
      } catch (err) {
        console.error(err);
        return new Response('Error: ' + err.message, { status: 500 });
      }
    }

    return new Response(
      `<h1>T3卡密查询机器人</h1>
       <p>状态：<b>运行中</b></p>
       <p>Webhook端点：<code>/webhook</code></p>
       <p>注册Webhook：<a href="/registerWebhook">/registerWebhook</a></p>`,
      { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  },
};