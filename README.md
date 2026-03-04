
# 🛡 ZeinaGuard Pro – Wireless Intrusion Detection & Prevention Engine (WIDPS)

## 📌 Overview

ZeinaGuard Pro WIDPS Engine هو نظام لمراقبة وتأمين الشبكات اللاسلكية (Wi-Fi) في الوقت الحقيقي.
يقوم النظام بـ:

* التقاط Beacon & Management Frames
* تحليل سلوك نقاط الوصول (Access Points)
* اكتشاف Rogue Access Points
* حساب Risk Score ديناميكي
* تنفيذ Active Containment (Deauthentication) في بيئة معملية
* إرسال الأحداث للنظام المركزي

النظام مصمم بهندسة modular قابلة للتوسعة وقريبة من أنظمة Enterprise الحقيقية.

---

# 🧠 Architecture Overview

```
Sniffer Layer
     ↓
Event Processor
     ↓
Threat Detection Engine
     ↓
Risk Scoring Engine
     ↓
Threat Manager
     ↓
Response Engine
     ↓
Containment Engine (Optional)
```

---

# 🧩 Core Modules

---

## 1️⃣ Monitoring Layer

### `monitoring/sniffer.py`

مسؤول عن:

* التقاط 802.11 frames باستخدام Scapy
* استخراج:

  * SSID
  * BSSID
  * Channel
  * Signal Strength (RSSI)
* تتبع العملاء المتصلين بكل BSSID
* تحديث `clients_map`

يعمل في وضع monitor mode على الواجهة المحددة في `config.py`.

---

## 2️⃣ Event Bus System

### `core/event_bus.py`

يعتمد على:

```python
Queue()
```

لنقل الأحداث بين الطبقات بشكل decoupled.

يضمن:

* عدم تداخل الطبقات
* قابلية التوسع


---

## 3️⃣ Threat Detection Engine

### `detection/threat_manager.py`

المسؤول عن:

* استقبال الأحداث من الـ Sniffer
* تحليلها مقابل:

  * trusted_aps
  * baseline behavior
* اكتشاف:

  * Rogue AP
  * SSID Spoofing
  * BSSID Mismatch
  * Channel anomalies
  * Signal manipulation

---

## 4️⃣ Risk Scoring System

كل تهديد يحصل على Score ديناميكي يعتمد على:

* تطابق SSID
* اختلاف BSSID
* عدد العملاء المتصلين
* قوة الإشارة
* سلوك غير طبيعي

مثال:

```
SSID match + BSSID mismatch = +40
Unexpected channel = +20
Clients connected = +30
```

لو تعدى الـ threshold → يتم اعتباره CONFIRMED THREAT.

---

## 5️⃣ Response Engine

### `prevention/response_engine.py`

عند تأكيد التهديد:

* يطبع تفاصيل كاملة
* يحدد:

  * SSID
  * BSSID
  * Score
  * Reasons
* يتحقق من تفعيل:

```python
ENABLE_ACTIVE_CONTAINMENT
```

---

## 6️⃣ Containment Engine

### `prevention/containment_engine.py`

* يجمع clients المرتبطين بالـ Rogue AP
* يرسل Deauthentication frames
* يستهدف:

  * BSSID
  * كل Client MAC متصل

الهدف:

* قطع الاتصال
* منع الاتصال بنقطة الوصول الخبيثة


---

# ⚙ Configuration Layer

### `config.py`

يتحكم في:

* Network Interface
* Enable / Disable Active Containment
* Threshold values
* Trusted Access Points
* Internal API settings

---

# 📡 Network Requirements

* Wireless adapter يدعم Monitor Mode
* Linux environment (Ubuntu / Kali)
* Scapy
* Root privileges

---

# 🧱 Design Principles

✔ Modular Architecture
✔ Event-Driven Processing
✔ Layer Separation
✔ Real-time Packet Inspection
✔ Dynamic Risk Scoring
✔ Optional Active Response

---

# 🔐 Detection Capabilities

* Rogue Access Point Detection
* SSID Spoofing Detection
* Evil Twin Behavior Recognition
* Unauthorized Client Association Monitoring
* Channel & Signal Anomaly Detection

---

# 🚀 Operational Flow

1. Sniffer يلتقط Beacon Frames
2. يتم استخراج metadata
3. يتم إرسال الحدث إلى Threat Engine
4. يتم حساب Risk Score
5. لو score > threshold:

   * يتم إعلان Confirmed Threat
   * يتم تفعيل Response Engine
   * يتم تنفيذ Containment (اختياري)

---

# 📊 Example Threat Output

```
🚨 CONFIRMED THREAT 🚨
SSID: WE_EDF20C
BSSID: 48:4C:29:XX:XX:XX
Score: 85
Reasons:
 - SSID matches trusted network
 - BSSID mismatch
 - Clients connected
 - Signal anomaly
---

# 🎓 Academic Value

المشروع يجمع بين:

* Wireless Communication Concepts
* Network Security
* Packet Analysis
* Real-time Processing
* Defensive Cybersecurity Engineering

ويمثل نموذج مبسط لأنظمة Wireless IDS/IPS المستخدمة في المؤسسات.


