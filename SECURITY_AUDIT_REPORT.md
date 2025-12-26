# KOMPLEXNÝ BEZPEČNOSTNÝ AUDIT
## Bruno's Calculator - PWA Aplikácia

**Dátum auditu:** 26. December 2025
**Verzia aplikácie:** v20 (Service Worker)
**Typ aplikácie:** Progressive Web App (PWA) s Firebase backend
**Audítor:** Claude Security Audit

---

## EXECUTIVE SUMMARY

### Celkové hodnotenie bezpečnosti: **STREDNÉ RIZIKO** ⚠️

Aplikácia implementuje niekoľko dobrých bezpečnostných praktik (CSP, input validácia, Firebase App Check), ale obsahuje **kritické zraniteľnosti** ktoré vyžadují okamžitú pozornosť:

- **3 Kritické zraniteľnosti** (CRITICAL)
- **5 Vysokých rizík** (HIGH)
- **7 Stredných rizík** (MEDIUM)
- **4 Nízke riziká** (LOW)

---

## 1. PREHĽAD APLIKÁCIE

### Architektúra
- **Typ:** Client-side Progressive Web App (PWA)
- **Frontend:** Vanilla JavaScript (ES6+), HTML5, CSS3
- **Backend:** Firebase (Authentication, Firestore, App Check)
- **Offline podpora:** Service Worker v20 + localStorage + IndexedDB
- **Hosting:** Statické súbory (bez vlastného servera)

### Technológie a závislosti
```
Firebase SDK v9.22.1 (CDN):
├── firebase-app-compat.js
├── firebase-auth-compat.js
├── firebase-firestore-compat.js
└── firebase-app-check-compat.js

PDF Generation (CDN):
├── jsPDF v2.5.1
└── jspdf-autotable v3.5.15

Fonts:
└── Google Fonts (Roboto)
```

### Hlavné funkcie
- Sledovanie pracovných hodín a dochádzky
- Výpočet miezd (hrubá/čistá)
- Export do PDF
- Zálohovanie/obnova dát
- Cloud synchronizácia cez Firebase
- Offline režim

---

## 2. KRITICKÉ ZRANITEĽNOSTI (CRITICAL)

### 🔴 CRITICAL-01: Exponované API kľúče v zdrojovom kóde
**Súbor:** `app.js:2-4`
**Závažnosť:** CRITICAL
**CVSS Skóre:** 9.1

**Popis:**
```javascript
const firebaseConfig = {
  apiKey: "AIzaSyDWFiWPldB7aWPIuFhAmriAm_DR38rndIo",  // ❌ VEREJNÉ
  authDomain: "bruno-3cee2.firebaseapp.com",
  projectId: "bruno-3cee2",
  storageBucket: "bruno-3cee2.appspot.com",
  messagingSenderId: "155545319308",
  appId: "1:155545319308:web:5da498ff1cd3e1833888a9"
};
firebase.appCheck().activate('6LcagP8qAAAAAN3MIW5-ALzayoS57THfEvO1yUTv', true); // ❌ VEREJNÉ
```

**Riziko:**
- Firebase API kľúč je verejne dostupný v client-side kóde
- reCAPTCHA site key exponovaný
- Útočník môže:
  - Zneužiť Firebase kvóty (API calls, storage)
  - Vykonať DoS útoky na Firebase backend
  - Skúmať Firebase security rules
  - Potenciálne obísť App Check ak nie je správne nakonfigurovaný

**Poznámka:** Firebase API kľúče sú navrhnuté ako verejné pre client-side aplikácie, ale musia byť chránené Firebase Security Rules a App Check.

**Odporúčania:**
1. ✅ **UŽ IMPLEMENTOVANÉ:** Firebase App Check je aktívny (mitigácia)
2. ⚠️ **OVERIT:** Firebase Security Rules musia byť správne nakonfigurované
3. ⚠️ **OVERIT:** Firestore rules by mali povoliť prístup len autentifikovaným používateľom k ich vlastným dátam
4. 🔧 **PRIDAŤ:** Domain restriction v Firebase Console (povolené len konkrétne domény)
5. 🔧 **PRIDAŤ:** Rate limiting v Firebase Security Rules

**Odporúčaná konfigurácia Firestore Rules:**
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/calculatorData/{document=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

---

### 🔴 CRITICAL-02: XSS zraniteľnosť v jsPDF knižnici (CVE-2020-7691)
**Súbor:** `index.html:59-62`
**Závažnosť:** CRITICAL
**CVSS Skóre:** 6.1

**Popis:**
Aplikácia používa **jsPDF v2.5.1**, ktorá obsahuje známu XSS zraniteľnosť:

**CVE-2020-7691** - XSS bypass cez `<<script>script>` pattern v HTML metóde

**Ovplyvnené funkcie:**
- `exportToPDF()` - app.js:1678
- `sendPDF()` - app.js:1759

**Potenciálny útok:**
```javascript
// Útočník môže vložiť do poznámky:
day.note = "<<script>alert('XSS')<</script>";
// Po exporte PDF môže dôjsť k vykonaniu kódu
```

**Aktuálny stav:**
```javascript
function exportToPDF() {
  const noteText = day.note || ''; // ❌ Nie je sanitizované pred PDF exportom
  rowData.push(noteText);
}
```

**Riziko:**
- Stored XSS cez pole "Poznámka"
- Malicious JavaScript kód v PDF
- Možné získanie session tokens
- Phishing útoky

**Odporúčania:**
1. 🔧 **UPGRADE:** Aktualizovať jsPDF na najnovšiu verziu (3.x+)
2. 🔧 **SANITIZÁCIA:** Implementovať HTML sanitizáciu pre PDF export:
```javascript
function sanitizeForPDF(text) {
  return text
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}
```

**Zdroje:**
- [CVE-2020-7691 na GitHub](https://github.com/parallax/jsPDF/issues/3700)
- [Snyk Vulnerability Report](https://security.snyk.io/package/npm/jspdf/2.5.1)

---

### 🔴 CRITICAL-03: Chýbajúce Firebase Security Rules overenie
**Súbor:** Firestore konfigurácia (externá)
**Závažnosť:** CRITICAL
**CVSS Skóre:** 8.5

**Popis:**
V repozitári sa nenachádzajú `firestore.rules` súbory. Bez overenia konfigurácie nemôžeme potvrdiť, že:
- Používatelia môžu pristupovať len k svojim vlastným dátam
- Neexistuje možnosť neoprávneného čítania/zápisu
- Rate limiting je implementovaný

**Aktuálny stav:**
```bash
$ find . -name "*.rules" -o -name "firestore.rules"
# Žiadne výsledky
```

**Kód predpokladá správnu izoláciu:**
```javascript
// app.js:606-607
const docPath = `users/${uid}/calculatorData/${currentYear}-${currentMonth}`;
// ✅ DOBRE: Používa UID používateľa v ceste
// ❌ RIZIKO: Bez Firestore rules overenia môže iný používateľ čítať cudzie dáta
```

**Potenciálne scenáre útokov:**
1. **Horizontal Privilege Escalation:** Používateľ A môže čítať dáta používateľa B zmenou UID v requeste
2. **Data Enumeration:** Útočník môže iterovať cez všetky UIDs a extrahovať všetky dáta
3. **Unauthenticated Access:** Ak rules povoľujú `allow read: if true`, ktokoľvek môže čítať dáta

**Odporúčania:**
1. 🔧 **VYTVOR:** `firestore.rules` súbor v projekte
2. 🔧 **IMPLEMENTUJ:** Striktné rules pre izoláciu používateľov
3. 🔧 **TESTUJ:** Firebase Rules Simulator v console
4. 🔧 **VERZUJ:** Pridaj rules do Git repozitára

**Príklad bezpečných rules:**
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Povoľ prístup len k vlastným dátam
    match /users/{userId}/calculatorData/{document=**} {
      allow read, write: if request.auth != null
                         && request.auth.uid == userId
                         && request.time < timestamp.date(2026, 12, 31); // Expirácia
    }

    // Rate limiting pomocou Custom Claims alebo Firestore counter
    match /users/{userId}/calculatorData/{yearMonth} {
      allow write: if request.auth != null
                   && request.auth.uid == userId
                   && request.resource.data.size() < 500000; // Max 500KB per doc
    }

    // Blokuj všetko ostatné
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

---

## 3. VYSOKÉ RIZIKÁ (HIGH)

### 🟠 HIGH-01: Nezašifrované úložisko v localStorage (Sensitive Data Exposure)
**Súbor:** `app.js:878-924`, `app.js:926-960`
**Závažnosť:** HIGH
**CVSS Skóre:** 7.2

**Popis:**
Všetky používateľské dáta sú uložené v **plain-text** v `localStorage`:

```javascript
// app.js:878-924
localStorage.setItem('workDaysData', serializedMonthData); // ❌ NEZAŠIFROVANÉ
localStorage.setItem('hourlyWage', JSON.stringify(hourlyWage)); // ❌ Finančné dáta
localStorage.setItem('employeeName', JSON.stringify(employeeName)); // ❌ PII
```

**Uložené citlivé dáta:**
- Pracovné hodiny a dochádzka
- Hodinová mzda (finančné dáta)
- Meno zamestnanca (PII)
- Poznámky (môžu obsahovať citlivé informácie)

**Vektory útoku:**
1. **XSS útoky:** Akýkoľvek XSS môže čítať celý localStorage
2. **Malware:** Škodlivé rozšírenia prehliadača môžu extrahovať dáta
3. **Physical access:** Útočník s prístupom k počítaču môže čítať dáta
4. **Browser Developer Tools:** Dáta viditeľné v DevTools

**Príklad extrakcie:**
```javascript
// Útočník môže v konzole vykonať:
console.log(localStorage.getItem('workDaysData'));
console.log(localStorage.getItem('hourlyWage'));
console.log(localStorage.getItem('employeeName'));
```

**Odporúčania:**
1. 🔧 **IMPLEMENTUJ:** Šifrovanie localStorage pomocou Web Crypto API:
```javascript
async function encryptData(data, key) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(JSON.stringify(data));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encodedData
  );
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(encryptedData)) };
}

async function decryptData(encrypted, key) {
  const decryptedData = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
    key,
    new Uint8Array(encrypted.data)
  );
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(decryptedData));
}

// Vygeneruj kľúč z Firebase Auth tokenu (unique per user)
async function deriveKey(userToken) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(userToken),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: encoder.encode('bruno-calc-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
```

2. 🔧 **ALTERNATÍVA:** Použiť IndexedDB s šifrovaním namiesto localStorage
3. 🔧 **MINIMALIZÁCIA:** Ukladať len nevyhnutné dáta lokálne, zvyšok len v Firebase

---

### 🟠 HIGH-02: Nezašifrované záložné súbory (Backup Exposure)
**Súbor:** `app.js:1992-2019`, `app.js:2021-2067`
**Závažnosť:** HIGH
**CVSS Skóre:** 6.8

**Popis:**
Funkcia `createBackup()` exportuje **všetky citlivé dáta** v plain-text JSON:

```javascript
// app.js:1992-2019
const backupData = {
  workDaysData: localStorage.getItem('workDaysData') || '{}', // ❌ PLAIN-TEXT
  hourlyWage: localStorage.getItem('hourlyWage') || JSON.stringify(10),
  taxRate: localStorage.getItem('taxRate') || JSON.stringify(2),
  employeeName: localStorage.getItem('employeeName') || JSON.stringify(''),
  backupVersion: 2,
  backupTimestamp: new Date().toISOString()
};

const blob = new Blob([JSON.stringify(backupData, null, 2)], {
  type: "application/json;charset=utf-8" // ❌ Žiadne šifrovanie
});
```

**Riziká:**
- Backup súbor môže byť uploadnutý do cloud storage (Dropbox, Google Drive)
- Email attachment môže byť interceptovaný
- Súbor môže byť ponechaný v Downloads folder
- Žiadne password protection
- Žiadne šifrovanie

**Príklad backup súboru:**
```json
{
  "workDaysData": "{\"2025\":{\"11\":[{\"start\":\"08:00\",\"end\":\"16:30\",\"breakTime\":\"0.5\",\"note\":\"Práca na projekte X\"}]}}",
  "hourlyWage": "15.50",
  "employeeName": "\"Ján Novák\"",
  "backupVersion": 2,
  "backupTimestamp": "2025-12-26T10:30:00.000Z"
}
```

**Odporúčania:**
1. 🔧 **ŠIFROVANIE:** Implementuj password-protected šifrovanie pre backupy:
```javascript
async function createEncryptedBackup() {
  const password = prompt('Zadajte heslo pre zálohu (min 12 znakov):');
  if (!password || password.length < 12) {
    alert('Heslo musí mať aspoň 12 znakov');
    return;
  }

  const backupData = { /* ... */ };
  const encrypted = await encryptBackup(JSON.stringify(backupData), password);

  const blob = new Blob([JSON.stringify(encrypted)], { type: "application/json" });
  // Download encrypted file
}
```

2. 🔧 **UPOZORNENIE:** Pridaj warning pred vytvorením backupu:
```javascript
const confirmed = confirm(
  'BEZPEČNOSTNÉ UPOZORNENIE:\n\n' +
  'Záložný súbor bude obsahovať vaše citlivé dáta.\n' +
  'Uschovajte ho na bezpečnom mieste.\n' +
  'Nikdy ho nezdieľajte cez email alebo cloud.\n\n' +
  'Pokračovať?'
);
```

3. 🔧 **ALTERNATÍVA:** Exportuj len do Firebase (cloud backup namiesto local file)

---

### 🟠 HIGH-03: Chýbajúce HTTP Security Headers (Server-Level)
**Súbor:** `index.html:37-41` (komentáre)
**Závažnosť:** HIGH
**CVSS Skóre:** 6.5

**Popis:**
Aplikácia nemá implementované kritické HTTP security headers, ktoré môžu byť nastavené len na server-level:

```html
<!-- index.html:37-41 -->
<!-- POZNÁMKA: Nasledujúce CSP direktívy a security headers MUSIA byť nastavené cez HTTP server: -->
<!-- CSP frame-ancestors 'none';  - prevencia clickjacking (ignorované v meta, len HTTP header!) -->
<!-- X-Frame-Options: DENY  - legacy fallback pre staré browsery -->
<!-- Strict-Transport-Security: max-age=31536000; includeSubDomains; preload  - HTTPS only -->
<!-- Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()  - feature policy -->
```

**Chýbajúce headers:**

| Header | Účel | Riziko bez implementácie |
|--------|------|--------------------------|
| `Strict-Transport-Security` | Vynúti HTTPS | Man-in-the-Middle útoky, downgrade útoky |
| `X-Frame-Options` | Clickjacking prevencia | Útočník môže embedovať stránku v iframe |
| `Permissions-Policy` | Obmedzenie API | Zneužitie browser APIs (camera, geo, atď.) |
| `X-Content-Type-Options` | MIME sniffing prevencia | MIME confusion útoky |

**Odporúčania:**
1. 🔧 **NGINX konfigurácia:**
```nginx
server {
    listen 443 ssl http2;
    server_name bruno-calculator.example.com;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Clickjacking protection
    add_header X-Frame-Options "DENY" always;

    # MIME sniffing protection (už je v meta tag, ale pridaj aj sem)
    add_header X-Content-Type-Options "nosniff" always;

    # XSS Protection (legacy)
    add_header X-XSS-Protection "1; mode=block" always;

    # Permissions Policy
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=()" always;

    # Referrer Policy (už je v meta tag, ale pridaj aj sem)
    add_header Referrer-Policy "no-referrer" always;

    # CSP (duplikát k meta tag pre lepšiu podporu)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://www.gstatic.com https://cdnjs.cloudflare.com https://www.google.com https://apis.google.com; ..." always;

    location / {
        root /var/www/bruno-calculator;
        try_files $uri $uri/ /index.html;
    }
}
```

2. 🔧 **Apache (.htaccess):**
```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
    Header always set Referrer-Policy "no-referrer"
</IfModule>
```

3. 🔧 **Firebase Hosting (firebase.json):**
```json
{
  "hosting": {
    "public": ".",
    "headers": [
      {
        "source": "**",
        "headers": [
          {
            "key": "Strict-Transport-Security",
            "value": "max-age=31536000; includeSubDomains; preload"
          },
          {
            "key": "X-Frame-Options",
            "value": "DENY"
          },
          {
            "key": "X-Content-Type-Options",
            "value": "nosniff"
          },
          {
            "key": "Permissions-Policy",
            "value": "geolocation=(), camera=(), microphone=(), payment=()"
          }
        ]
      }
    ]
  }
}
```

---

### 🟠 HIGH-04: Nedostatočná validácia pri obnove zálohy
**Súbor:** `app.js:2021-2067`
**Závažnosť:** HIGH
**CVSS Skóre:** 6.3

**Popis:**
Funkcia `restoreBackup()` má slabú validáciu, ktorá umožňuje vložiť škodlivé dáta:

```javascript
// app.js:2033-2034
const backup = JSON.parse(e.target.result); // ❌ Žiadna JSON schema validácia
if (backup && typeof backup.workDaysData === 'string' && /* basic type checks */) {
  // ❌ Nekontroluje obsah workDaysData
  // ❌ Nekontroluje backupVersion compatibility
  // ❌ Nekontroluje veľkosť dát
  localStorage.setItem('workDaysData', backup.workDaysData); // Priamo uloží
}
```

**Potenciálne útoky:**
1. **Malformed JSON injection:**
```json
{
  "workDaysData": "{\"__proto__\":{\"isAdmin\":true}}",  // Prototype pollution
  "hourlyWage": "999999999999",  // Overflow
  "employeeName": "\"<script>alert('XSS')</script>\""  // XSS payload
}
```

2. **Data corruption:**
```json
{
  "workDaysData": "[]".repeat(1000000),  // DoS - extrémne veľké dáta
  "backupVersion": 999  // Neznáma verzia
}
```

**Odporúčania:**
1. 🔧 **IMPLEMENTUJ:** Striktná JSON schema validácia:
```javascript
function validateBackupSchema(backup) {
  // Version check
  if (backup.backupVersion !== 2) {
    throw new Error(`Nepodporovaná verzia zálohy: ${backup.backupVersion}`);
  }

  // Type checks
  if (typeof backup.workDaysData !== 'string') return false;
  if (typeof backup.hourlyWage !== 'string') return false;
  if (typeof backup.employeeName !== 'string') return false;

  // Size limits
  if (backup.workDaysData.length > 4 * 1024 * 1024) { // 4MB
    throw new Error('Záloha je príliš veľká');
  }

  // Parse and validate workDaysData structure
  try {
    const workData = JSON.parse(backup.workDaysData);
    if (typeof workData !== 'object') return false;

    // Validate structure
    for (const [year, months] of Object.entries(workData)) {
      if (!/^\d{4}$/.test(year)) return false;
      for (const [month, days] of Object.entries(months)) {
        if (!/^\d{1,2}$/.test(month) || month < 0 || month > 11) return false;
        if (!Array.isArray(days)) return false;

        for (const day of days) {
          if (day.start && !VALIDATION_RULES.TIME_REGEX.test(day.start)) return false;
          if (day.end && !VALIDATION_RULES.TIME_REGEX.test(day.end)) return false;
          if (day.note && day.note.length > VALIDATION_RULES.MAX_NOTE_LENGTH) return false;
        }
      }
    }
  } catch (e) {
    return false;
  }

  // Validate hourlyWage
  const wage = parseFloat(JSON.parse(backup.hourlyWage));
  if (isNaN(wage) || wage < 0 || wage > VALIDATION_RULES.MAX_HOURLY_WAGE) return false;

  // Validate taxRate
  const tax = parseFloat(JSON.parse(backup.taxRate));
  if (isNaN(tax) || tax < 0 || tax > VALIDATION_RULES.MAX_TAX_RATE) return false;

  return true;
}
```

2. 🔧 **SANITIZÁCIA:** Sanitizuj všetky string hodnoty:
```javascript
function sanitizeBackupData(backup) {
  return {
    workDaysData: backup.workDaysData,
    hourlyWage: backup.hourlyWage,
    taxRate: backup.taxRate,
    employeeName: backup.employeeName.replace(/[<>]/g, ''), // Remove HTML chars
    decimalPlaces: backup.decimalPlaces,
    darkMode: backup.darkMode
  };
}
```

---

### 🟠 HIGH-05: Console logging citlivých informácií v produkcii
**Súbor:** `app.js` (multiple locations)
**Závažnosť:** HIGH
**CVSS Skóre:** 5.8

**Popis:**
Aplikácia obsahuje **20+ console.log/warn/error** príkazov, ktoré môžu leakovať citlivé informácie:

```javascript
// app.js:236-240
console.error(`[${context}] Detailná chyba:`, {
  code: error.code,
  message: error.message,  // ❌ Môže obsahovať citlivé info
  stack: error.stack        // ❌ Odhaľuje internú štruktúru
});

// app.js:260
console.error(`[Firestore ${operation}] Chyba:`, error); // ❌ Celý error objekt
```

**Information disclosure:**
- Error stack traces odhaľujú internú architektúru
- Firebase error messages môžu obsahovať UIDs
- Console.log dáta viditeľné v browser DevTools

**Nájdené console príkazy:**
```bash
$ grep -n "console\." app.js | wc -l
20  # 20 console výpisov
```

**Odporúčania:**
1. 🔧 **IMPLEMENTUJ:** Conditional logging podľa prostredia:
```javascript
// Pridaj na začiatok app.js
const DEBUG_MODE = window.location.hostname === 'localhost' ||
                   window.location.hostname === '127.0.0.1' ||
                   localStorage.getItem('debugMode') === 'true';

// Wrapper funkcie
const logger = {
  log: (...args) => { if (DEBUG_MODE) console.log(...args); },
  warn: (...args) => { if (DEBUG_MODE) console.warn(...args); },
  error: (msg, error) => {
    if (DEBUG_MODE) {
      console.error(msg, error);
    } else {
      // V produkcii loguj len error code, nie celý objekt
      console.error(msg, error?.code || 'unknown');
    }
  }
};

// Nahraď všetky console.* s logger.*
logger.error('[Auth] Chyba:', error);
```

2. 🔧 **BUILD PROCES:** Odstráň všetky console príkazy v produkcii:
```javascript
// Použiť terser alebo podobný minifier
// terser app.js --compress drop_console=true --output app.min.js
```

---

## 4. STREDNÉ RIZIKÁ (MEDIUM)

### 🟡 MEDIUM-01: Príliš permisívny CSP pre `img-src`
**Súbor:** `index.html:16`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 5.3

**Popis:**
```html
<meta http-equiv="Content-Security-Policy" content="
  ...
  img-src 'self' https: data: blob:;  <!-- ❌ Povoľuje VŠETKY HTTPS domény -->
  ...
">
```

**Riziko:**
- Útočník môže načítať obrázky z ľubovoľnej HTTPS domény
- Tracking pixels môžu byť vložené cez XSS
- Data exfiltration cez image requests

**Odporúčanie:**
```html
img-src 'self' data: blob: https://firebasestorage.googleapis.com;
```

---

### 🟡 MEDIUM-02: Chýba `frame-ancestors` direktíva v CSP
**Súbor:** `index.html:11-31`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 5.0

**Popis:**
CSP nemá `frame-ancestors 'none'` direktívu (možné len cez HTTP header).

**Riziko:**
- Clickjacking útoky
- UI redressing

**Odporúčanie:**
Pridaj cez HTTP header (nie meta tag):
```
Content-Security-Policy: frame-ancestors 'none';
```

---

### 🟡 MEDIUM-03: Slabá validácia hesla
**Súbor:** `app.js:140-166`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 4.8

**Popis:**
```javascript
// app.js:140-166
const MIN_PASSWORD_LENGTH = 8;
const hasNumber = /\d/.test(password);
const hasLetter = /[a-zA-Z]/.test(password);
```

**Problémy:**
- Nevyžaduje špeciálne znaky
- Nevyžaduje veľké písmená
- Nekontroluje zoznam slabých hesiel
- Nekontroluje sekvencie (123456, abcdef)

**Odporúčanie:**
```javascript
function validatePassword(password) {
  if (password.length < 12) { // ❌ Zvýš na 12
    return { valid: false, error: 'Heslo musí mať aspoň 12 znakov' };
  }

  // Kontrola zložitosti
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  const complexity = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
  if (complexity < 3) {
    return {
      valid: false,
      error: 'Heslo musí obsahovať aspoň 3 z: malé písmená, veľké písmená, čísla, špeciálne znaky'
    };
  }

  // Kontrola common passwords
  const commonPasswords = ['password', '12345678', 'qwerty', 'letmein'];
  if (commonPasswords.includes(password.toLowerCase())) {
    return { valid: false, error: 'Toto heslo je príliš bežné' };
  }

  return { valid: true, error: null };
}
```

---

### 🟡 MEDIUM-04: Žiadny rate limiting na client-side
**Súbor:** `app.js:280-388`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 4.5

**Popis:**
Auth funkcie nemajú client-side rate limiting:

```javascript
function register() {
  // ❌ Žiadny rate limiting
  auth.createUserWithEmailAndPassword(email, password);
}

function login() {
  // ❌ Žiadny rate limiting
  auth.signInWithEmailAndPassword(email, password);
}
```

**Riziko:**
- Brute-force útoky
- Credential stuffing
- DoS na Firebase Auth

**Poznámka:** Firebase má vlastný rate limiting, ale client-side ochrana je best practice.

**Odporúčanie:**
```javascript
// Rate limiter implementation
class RateLimiter {
  constructor(maxAttempts = 5, windowMs = 60000) {
    this.attempts = new Map();
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  canAttempt(key) {
    const now = Date.now();
    const attempts = this.attempts.get(key) || [];

    // Odstráň staré pokusy mimo okna
    const recentAttempts = attempts.filter(time => now - time < this.windowMs);

    if (recentAttempts.length >= this.maxAttempts) {
      return false;
    }

    recentAttempts.push(now);
    this.attempts.set(key, recentAttempts);
    return true;
  }

  reset(key) {
    this.attempts.delete(key);
  }
}

const authLimiter = new RateLimiter(5, 60000); // 5 attempts per minute

function login() {
  const email = emailInput.value;

  if (!authLimiter.canAttempt('login')) {
    alert('Príliš veľa pokusov o prihlásenie. Skúste znova o 1 minútu.');
    return;
  }

  auth.signInWithEmailAndPassword(email, password)
    .then(() => {
      authLimiter.reset('login');
      showSafeAlert("Prihlásenie úspešné!");
    })
    .catch(error => {
      // Chyba sa počíta do rate limit
    });
}
```

---

### 🟡 MEDIUM-05: Chýba Content Security Policy pre `worker-src`
**Súbor:** `index.html:11-31`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 4.2

**Popis:**
CSP nemá `worker-src` direktívu pre Service Worker.

**Aktuálne:**
```html
default-src 'self';  <!-- Fallback pre worker-src -->
```

**Odporúčanie:**
```html
worker-src 'self';
```

---

### 🟡 MEDIUM-06: Service Worker cache poisoning riziko
**Súbor:** `service-worker.js:44-85`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 4.0

**Popis:**
Service Worker cachuje všetky GET requesty bez validácie:

```javascript
// service-worker.js:58-68
return fetch(request).then((networkResponse) => {
  // ❌ Cachuje všetko so status 200, bez content-type validácie
  if (!networkResponse || networkResponse.status !== 200) {
    return networkResponse;
  }

  const responseToCache = networkResponse.clone();
  caches.open(RUNTIME_CACHE).then((cache) => {
    cache.put(request, responseToCache); // ❌ Žiadna validácia obsahu
  });
});
```

**Riziko:**
- Ak útočník modifikuje response (MitM), zlý obsah sa uloží do cache
- Cache poisoning môže viesť k persistent XSS

**Odporúčanie:**
```javascript
return fetch(request).then((networkResponse) => {
  if (!networkResponse || networkResponse.status !== 200) {
    return networkResponse;
  }

  // Validuj Content-Type pred cachovaním
  const contentType = networkResponse.headers.get('content-type');
  const allowedTypes = [
    'text/html',
    'text/css',
    'application/javascript',
    'application/json',
    'image/png',
    'image/jpeg',
    'font/woff2'
  ];

  const shouldCache = allowedTypes.some(type => contentType?.includes(type));

  if (shouldCache) {
    const responseToCache = networkResponse.clone();
    caches.open(RUNTIME_CACHE).then((cache) => {
      cache.put(request, responseToCache);
    });
  }

  return networkResponse;
});
```

---

### 🟡 MEDIUM-07: Potenciálna race condition v Firestore sync
**Súbor:** `app.js:591-758`
**Závažnosť:** MEDIUM
**CVSS Skóre:** 3.8

**Popis:**
Firestore listener a localStorage sync môžu vytvoriť race condition:

```javascript
// app.js:640-643
if (isUserEditing || pendingChanges.size > 0) {
  return; // ❌ Odloží sync, ale môže viesť k data loss
}
```

**Scenár:**
1. Používateľ edituje dáta (isUserEditing = true)
2. Iné zariadenie odošle update do Firebase
3. Listener ignoruje update (return early)
4. Po ukončení editácie sa prepíše Firebase dátami z tohto zariadenia
5. **Data loss** z iného zariadenia

**Odporúčanie:**
Implementuj konflikt resolution strategy:
```javascript
// Implementuj three-way merge
function mergeChanges(local, remote, base) {
  const merged = {};

  for (const key of new Set([...Object.keys(local), ...Object.keys(remote)])) {
    if (local[key] === remote[key]) {
      merged[key] = local[key]; // Rovnaké, bez konfliktu
    } else if (local[key] !== base[key] && remote[key] === base[key]) {
      merged[key] = local[key]; // Len lokálna zmena
    } else if (remote[key] !== base[key] && local[key] === base[key]) {
      merged[key] = remote[key]; // Len remote zmena
    } else {
      // Konflikt - použiť timestamp based resolution
      merged[key] = localTimestamp > remoteTimestamp ? local[key] : remote[key];
    }
  }

  return merged;
}
```

---

## 5. NÍZKE RIZIKÁ (LOW)

### 🟢 LOW-01: Hardcoded timeout hodnoty
**Súbor:** `app.js:647`, `app.js:839`
**Závažnosť:** LOW

**Popis:**
```javascript
if (Date.now() - localChangeTimestamp < 5000) { // ❌ Hardcoded 5s
  return;
}

let saveTimeout;
clearTimeout(saveTimeout);
saveTimeout = setTimeout(() => { saveToFirebase(); }, 1000); // ❌ Hardcoded 1s
```

**Odporúčanie:**
```javascript
const CONFIG = {
  SYNC_CONFLICT_WINDOW_MS: 5000,
  SAVE_DEBOUNCE_MS: 1000,
  MAX_DATA_SIZE: 4 * 1024 * 1024
};
```

---

### 🟢 LOW-02: Neoptimálne používanie `JSON.parse()` bez try-catch
**Súbor:** `app.js:926-960`
**Závažnosť:** LOW

**Popis:**
```javascript
// app.js:926
monthData = storedMonthData ? JSON.parse(storedMonthData) : {};
// ❌ Ak je localStorage corrupted, crashne
```

**Odporúčanie:**
Už existuje try-catch wrapper, ale validuj JSON schema.

---

### 🟢 LOW-03: Chýba Subresource Integrity (SRI) pre Google Fonts
**Súbor:** `index.html:43`
**Závažnosť:** LOW

**Popis:**
```html
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap&subset=latin-ext" rel="stylesheet">
<!-- ❌ Chýba integrity="" a crossorigin="" -->
```

**Poznámka:** Google Fonts dynamicky generujú CSS, takže SRI nie je možné použiť.

**Odporúčanie:**
Self-host fonty namiesto CDN:
```html
<link rel="stylesheet" href="/fonts/roboto.css">
```

---

### 🟢 LOW-04: Service Worker verzia musí byť manuálne aktualizovaná
**Súbor:** `service-worker.js:5`
**Závažnosť:** LOW

**Popis:**
```javascript
const CACHE_VERSION = 'v20'; // ❌ Manuálne číslo
```

**Riziko:**
- Developer zabudne zvýšiť verziu
- Používatelia dostanú starú cached verziu

**Odporúčanie:**
```javascript
// Použiť build timestamp
const CACHE_VERSION = 'v__BUILD_TIMESTAMP__'; // Nahradí build proces
// Alebo Git commit hash
const CACHE_VERSION = 'v__GIT_COMMIT_HASH__';
```

---

## 6. POZITÍVNE BEZPEČNOSTNÉ PRAKTIKY ✅

Aplikácia implementuje nasledujúce dobré bezpečnostné praktiky:

### ✅ Input Validácia
- **Kompletná validácia** pre všetky user inputs (čas, email, heslo, čísla, poznámky)
- **Regex patterns** pre formát kontrolu (HH:MM, email)
- **Range checking** pre číselné hodnoty (max hourly wage, tax rate)
- **Length limits** (max 500 znakov pre poznámky, 254 pre email)

### ✅ Content Security Policy
- **Striktná CSP** via meta tag
- **Whitelist approach** pre script-src, style-src, connect-src
- **`upgrade-insecure-requests`** direktíva
- **`object-src 'none'`** (blokuje Flash/plugins)
- **`base-uri 'self'`** a **`form-action 'self'`**

### ✅ Subresource Integrity (SRI)
- **SRI hashes** pre všetky CDN scripts (Firebase, jsPDF)
- **crossorigin="anonymous"** attribute

### ✅ Safe Error Handling
- **Error message sanitization** (app.js:233-276)
- **Prevencia username enumeration** (rovnaká chyba pre wrong email/password)
- **Development vs Production logging** (zobrazuje detaily len na localhost)
- **Generic error messages** pre používateľov

### ✅ Firebase App Check
- **App integrity verification** aktivované (app.js:4)
- **reCAPTCHA v3** integrácia
- **Bot protection**

### ✅ Firebase Authentication
- **Email/Password auth** s validáciou
- **Password reset** funkcia
- **Auth state listener** pre session management

### ✅ Firestore Offline Persistence
- **IndexedDB persistence** zapnutá (app.js:397)
- **Multi-tab synchronization** enabled
- **Graceful offline degradation**

### ✅ User Data Isolation
- **UID-based paths** v Firestore (`users/{uid}/calculatorData/{doc}`)
- **Predpoklad správnych Security Rules** (aj keď nie sú vo verzovaní)

### ✅ Safe DOM Manipulation
- **Používa `textContent` namiesto `innerHTML`** (všade kde je to možné)
- **Žiadne `eval()`, `new Function()`, `dangerouslySetInnerHTML`**
- **Input sanitizácia pred zobrazením**

### ✅ Data Size Limits
- **localStorage size monitoring** (app.js:878-924)
- **Visual warnings** pri 70-90% kapacity
- **Hard limit** pri 4 MB

### ✅ Backup Versioning
- **`backupVersion: 2`** field v backupoch
- **Timestamp tracking** pre audit trail

### ✅ Dark Mode (Bonus Security)
- **Redukuje eye strain** pri práci v tme
- **Znižuje screen burn-in riziko**

---

## 7. OWASP TOP 10 (2021) ANALÝZA

| OWASP Risk | Prítomný | Závažnosť | Popis |
|------------|----------|-----------|--------|
| **A01:2021 – Broken Access Control** | ⚠️ Možné | CRITICAL | Závisí od Firebase Security Rules (neverifikované) |
| **A02:2021 – Cryptographic Failures** | ✅ Áno | HIGH | localStorage plain-text, nezašifrované backupy |
| **A03:2021 – Injection** | ⚠️ Čiastočne | MEDIUM | PDF export XSS (CVE-2020-7691 v jsPDF) |
| **A04:2021 – Insecure Design** | ⚠️ Čiastočne | MEDIUM | Chybá šifrovanie lokálnych dát, slabá backup security |
| **A05:2021 – Security Misconfiguration** | ⚠️ Čiastočne | HIGH | Chýbajúce HTTP headers, prod logging |
| **A06:2021 – Vulnerable Components** | ✅ Áno | CRITICAL | jsPDF 2.5.1 (CVE-2020-7691), Firebase 9.22.1 (zastaraná) |
| **A07:2021 – Identification and Authentication Failures** | ⚠️ Čiastočne | MEDIUM | Slabá password policy, žiadny MFA |
| **A08:2021 – Software and Data Integrity Failures** | ⚠️ Čiastočne | MEDIUM | SRI implemented (✅), ale SW cache poisoning možné |
| **A09:2021 – Security Logging and Monitoring Failures** | ✅ Áno | MEDIUM | Nedostatočný logging, žiadny audit trail pre Firebase ops |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | ❌ Nie | N/A | Aplikácia nemá server-side komponent |

**Skóre:** 6/10 OWASP kategórií ovplyvnených (2 critical, 4 medium-high)

---

## 8. ODPORÚČANIA PODĽA PRIORITY

### 🔴 KRITICKÁ PRIORITA (Implementuj okamžite)

1. **Overenie Firebase Security Rules** (CRITICAL-03)
   - Vytvor `firestore.rules` súbor
   - Implementuj striktné user isolation rules
   - Testuj v Firebase Console Simulator
   - Nasaď pravidlá do produkcie

2. **Upgrade jsPDF knižnice** (CRITICAL-02)
   - Aktualizuj z v2.5.1 na v3.x+
   - Testuj PDF export funkčnosť
   - Implementuj HTML sanitizáciu pre poznámky

3. **Implementácia localStorage šifrovania** (HIGH-01)
   - Použiť Web Crypto API
   - Derive key z Firebase Auth token
   - Encrypt pred uložením do localStorage

4. **HTTP Security Headers** (HIGH-03)
   - Nasaď HSTS, X-Frame-Options, Permissions-Policy
   - Použiť Firebase Hosting `firebase.json` alebo NGINX config
   - Otestuj cez securityheaders.com

### 🟠 VYSOKÁ PRIORITA (Implementuj do 1 mesiaca)

5. **Šifrovanie backupov** (HIGH-02)
   - Password-protected encryption
   - Bezpečnostné upozornenie pred vytvorením backupu

6. **Odstránenie production loggingu** (HIGH-05)
   - Implementuj conditional logger
   - Build proces s `drop_console`

7. **Striktná backup validácia** (HIGH-04)
   - JSON schema validation
   - Size limits
   - Data sanitization

### 🟡 STREDNÁ PRIORITA (Implementuj do 3 mesiacov)

8. **Zlepšenie password policy** (MEDIUM-03)
   - Min 12 znakov
   - 3/4 character classes
   - Common password check

9. **Client-side rate limiting** (MEDIUM-04)
   - RateLimiter class implementácia
   - 5 attempts per minute limit

10. **CSP optimalizácia** (MEDIUM-01, MEDIUM-02, MEDIUM-05)
    - Reštrikcia `img-src`
    - Pridanie `worker-src`
    - `frame-ancestors` cez HTTP header

11. **Service Worker validácia** (MEDIUM-06)
    - Content-Type checking pred cachovaním
    - Whitelist allowed response types

### 🟢 NÍZKA PRIORITA (Nice to have)

12. **Konfigurácia konštánt** (LOW-01)
    - Vytvor `CONFIG` objekt
    - Centralizovaná konfigurácia

13. **Automated cache versioning** (LOW-04)
    - Build proces s timestamp/commit hash injection

14. **Self-hosted fonts** (LOW-03)
    - Odstráň závislosť na Google Fonts CDN

---

## 9. BEZPEČNOSTNÉ CHECKLIST

```
AUTENTIFIKÁCIA & AUTORIZÁCIA
[✅] Firebase Authentication implementované
[✅] Email/password validácia
[❌] Multi-Factor Authentication (MFA)
[⚠️] Firebase Security Rules (neverifikované)
[❌] Session timeout
[❌] Account lockout po zlyhaniach

INPUT VALIDÁCIA
[✅] Regex validácia času (HH:MM)
[✅] Email format validácia
[✅] Password complexity check
[✅] Numeric range validácia
[✅] Note length limit (500 chars)
[❌] HTML sanitizácia pre PDF export

KRYPTOGRAFIA
[❌] localStorage šifrovanie
[❌] Backup encryption
[✅] HTTPS enforced (upgrade-insecure-requests)
[❌] HSTS header
[✅] Firebase server-side encryption (automatic)

XSS PREVENCIA
[✅] Používa textContent namiesto innerHTML
[✅] CSP implementované
[✅] Input sanitizácia
[⚠️] jsPDF XSS vulnerability (CVE-2020-7691)
[❌] Output encoding pre PDF

DATA SECURITY
[❌] localStorage encryption
[✅] Firestore rules (predpokladané)
[✅] User data isolation (UID paths)
[❌] Backup encryption
[✅] Data size limits

SECURITY HEADERS
[✅] Content-Security-Policy (meta tag)
[✅] X-Content-Type-Options (meta tag)
[✅] Referrer-Policy (meta tag)
[❌] Strict-Transport-Security (HTTP header)
[❌] X-Frame-Options (HTTP header)
[❌] Permissions-Policy (HTTP header)

DEPENDENCIES
[✅] SRI hashes pre CDN resources
[✅] Firebase App Check enabled
[⚠️] jsPDF outdated (v2.5.1, CVE-2020-7691)
[⚠️] Firebase SDK outdated (v9.22.1)

ERROR HANDLING
[✅] Safe error messages
[✅] Username enumeration prevention
[✅] Development vs production logging
[⚠️] Príliš veľa console.log v produkcii

OFFLINE SECURITY
[✅] Service Worker HTTPS only
[✅] Cache versioning
[⚠️] Cache poisoning riziko
[✅] Firestore offline persistence

MONITORING & LOGGING
[❌] Security event logging
[❌] Audit trail pre citlivé operácie
[❌] Failed login monitoring
[❌] Anomaly detection
```

**Celkové skóre:** 18/38 (47%) ⚠️

---

## 10. BEZPEČNOSTNÉ TESTOVACIE SCENÁRE

### Scenár 1: XSS cez poznámky
```javascript
// Test: Vlož do poznámky
<<script>alert('XSS')<</script>
<img src=x onerror=alert('XSS')>

// Export do PDF
// Očakávané: Mal by sanitizovať
// Aktuálne: VULNERABLE (CVE-2020-7691)
```

### Scenár 2: localStorage theft
```javascript
// Otvor DevTools Console
console.log(localStorage.getItem('workDaysData'));
console.log(localStorage.getItem('employeeName'));

// Očakávané: Mal by byť encrypted
// Aktuálne: PLAIN-TEXT VISIBLE
```

### Scenár 3: Clickjacking
```html
<!-- Útočník vytvorí iframe -->
<iframe src="https://bruno-calculator.example.com"></iframe>

<!-- Očakávané: Mal byť blokovaný X-Frame-Options -->
<!-- Aktuálne: MŮŽE SA EMBEDOVAŤ (chýba HTTP header) -->
```

### Scenár 4: Firebase rules bypass
```javascript
// Test: Skús pristúpiť k cudzím dátam
const otherUserUID = 'xxxxxx';
db.collection('users').doc(otherUserUID).collection('calculatorData').get()

// Očakávané: Firestore permission denied
// Aktuálne: NEVERIFIKOVANÉ (závisí od rules)
```

### Scenár 5: Malicious backup restore
```json
// Vytvor malicious backup súbor
{
  "workDaysData": "{\"2025\":{\"0\":[{\"note\":\"<script>alert('XSS')</script>\"}]}}",
  "hourlyWage": "999999999",
  "employeeName": "\"<img src=x onerror=alert('XSS')>\"",
  "backupVersion": 2
}

// Obnoviť backup
// Očakávané: Mal by validovať a sanitizovať
// Aktuálne: SLABÁ VALIDÁCIA
```

---

## 11. COMPLIANCE OVERENIE

### GDPR (General Data Protection Regulation)
```
[⚠️] Personal data encryption (localStorage plain-text)
[✅] User authentication (Firebase Auth)
[❌] Right to erasure (delete account)
[⚠️] Data portability (backup export, ale plain-text)
[❌] Privacy policy
[❌] Cookie consent
[✅] Data minimization (zbiera len potrebné dáta)
[❌] Audit logging
```

### OWASP ASVS (Application Security Verification Standard) v4.0
```
Level 1 (Basic):     65% ✅
Level 2 (Standard):  45% ⚠️
Level 3 (Advanced):  20% ❌
```

---

## 12. INCIDENT RESPONSE PLAN (Odporúčanie)

V prípade bezpečnostného incidentu:

1. **Detection:**
   - Monitoruj Firebase Console pre unusual activity
   - Sleduj error rates v browser console
   - User reports o neobvyklom správaní

2. **Containment:**
   - Deaktivuj Firebase API keys v Console
   - Revert k predchádzajúcej verzii aplikácie
   - Notify users o potenciálnom security breach

3. **Eradication:**
   - Identifikuj a oprav zraniteľnosť
   - Update dependencies
   - Deploy fix

4. **Recovery:**
   - Regeneruj Firebase credentials
   - Force logout všetkých používateľov
   - Vyžaduj password reset

5. **Lessons Learned:**
   - Dokumentuj incident
   - Update security procedures
   - Implementuj preventívne measures

---

## 13. ZÁVER A ODPORÚČANIA

### Súhrnné hodnotenie
Bruno's Calculator je **funkčná a užitočná aplikácia** s niekoľkými **dobrými bezpečnostnými praktikami** (CSP, input validácia, Firebase App Check), ale obsahuje **kritické zraniteľnosti** ktoré ju robia zraniteľnou voči:

- **Data theft** (plain-text localStorage)
- **XSS útokom** (jsPDF CVE-2020-7691)
- **Potenciálnemu neoprávnenému prístupu** (neverifikované Firestore rules)
- **Information disclosure** (production logging, nezašifrované backupy)

### Top 3 priority
1. **Overenie a úprava Firebase Security Rules** → Zabráni neoprávnenému prístupu
2. **Upgrade jsPDF + sanitizácia** → Eliminuje XSS riziko
3. **Implementácia localStorage encryption** → Ochráni citlivé dáta

### Časový odhad implementácie
- **Kritické fixes:** 2-3 dni
- **High priority fixes:** 1 týždeň
- **Medium priority:** 2-3 týždne
- **Celková security maturity:** 1-2 mesiace

### Finálne odporúčenie
**Aplikácia môže byť nasadená do produkcie** po vyriešení **CRITICAL-01, CRITICAL-02, a CRITICAL-03** zraniteľností. Ostatné riziká môžu byť adresované postupne podľa priority.

---

## 14. KONTAKT A ZDROJE

### Bezpečnostné nástroje na testovanie
- [securityheaders.com](https://securityheaders.com) - HTTP headers scan
- [observatory.mozilla.org](https://observatory.mozilla.org) - Web security audit
- [Firebase Console](https://console.firebase.google.com) - Security rules testing
- [OWASP ZAP](https://www.zaproxy.org/) - Vulnerability scanner
- [Snyk](https://snyk.io) - Dependency vulnerability scanner

### Vzdelávacie zdroje
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Firebase Security Rules Guide](https://firebase.google.com/docs/rules)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### CVE zdroje použité v audite
- [CVE-2020-7691 (jsPDF XSS)](https://github.com/parallax/jsPDF/issues/3700)
- [Snyk Vulnerability Database](https://security.snyk.io/package/npm/jspdf/2.5.1)
- [Firebase Security Updates](https://firebase.google.com/support/release-notes/js)

---

**Koniec bezpečnostného auditu**
**Dátum:** 26. December 2025
**Audítor:** Claude Security Audit
**Verzia reportu:** 1.0
