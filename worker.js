export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. 注册 Webhook 的端点
    if (url.pathname === '/registerWebhook') {
      const webhookUrl = `${url.origin}/webhook`;
      const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`);
      const data = await res.json();
      return new Response(`<h1>Webhook注册结果</h1><pre>${JSON.stringify(data, null, 2)}</pre>`, { headers: { 'Content-Type': 'text/html' } });
    }

    // 2. 接收消息
    if (url.pathname === '/webhook' && request.method === 'POST') {
      try {
        const update = await request.json();
        console.log("收到消息:", JSON.stringify(update)); // 日志里会打印收到的内容

        if (update.message && update.message.text) {
          const chatId = update.message.chat.id;
          const text = update.message.text;
          
          // 直接回复消息
          await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text: `收到您的消息：${text}` })
          });
        }
        return new Response('OK', { status: 200 });
      } catch (e) {
        console.error("严重错误:", e.message); // 如果有错误，日志里能看到红字
        return new Response('Error: ' + e.message, { status: 500 });
      }
    }

    return new Response('Worker 正在运行中');
  }
}
