import dotenv from 'dotenv';
import https from 'https';

dotenv.config();

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const WEB_APP_URL = process.env.CLIENT_URL || 'https://stately-bavarois-bb998f.netlify.app';

if (!BOT_TOKEN) {
  console.error('❌ خطأ: يرجى ضبط TELEGRAM_BOT_TOKEN في متغيرات البيئة (.env)');
} else {
  console.log('🤖 جاري تشغيل بوت تيليجرام...');
  console.log(`🔗 رابط الـ Web App: ${WEB_APP_URL}`);

  let offset = 0;

  function makeRequest(method, data) {
    return new Promise((resolve, reject) => {
      const payload = JSON.stringify(data);
      const req = https.request(
        `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          }
        },
        (res) => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            try {
              resolve(JSON.parse(body));
            } catch (err) {
              reject(err);
            }
          });
        }
      );
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  async function pollUpdates() {
    try {
      const response = await makeRequest('getUpdates', {
        offset,
        timeout: 30
      });

      if (response.ok && Array.isArray(response.result)) {
        for (const update of response.result) {
          offset = update.update_id + 1;
          if (update.message && update.message.text) {
            const chatId = update.message.chat.id;
            const text = update.message.text.trim();

            if (text.startsWith('/start')) {
              await makeRequest('sendMessage', {
                chat_id: chatId,
                text: 'أهلاً بك في منظومة إدارة المدارس 🏫✨\n\nاضغط على الزر أدناه لفتح التطبيق داخل تيليجرام:',
                reply_markup: {
                  inline_keyboard: [
                    [
                      {
                        text: '🚀 فتح منظومة إدارة المدارس',
                        web_app: { url: WEB_APP_URL }
                      }
                    ]
                  ]
                }
              });
            }
          }
        }
      }
    } catch (error) {
      console.error('خطأ أثناء جلب التحديثات من تيليجرام:', error.message);
      await new Promise(r => setTimeout(r, 5000));
    }
    setImmediate(pollUpdates);
  }

  pollUpdates();
}
