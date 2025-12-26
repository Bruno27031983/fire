# GitHub Pages Security Addendum
## Bezpečnostný audit - Špecifické obmedzenia pre GitHub Pages

**Dátum:** 26. December 2025
**Hosting:** GitHub Pages (statický hosting)
**Súvisí s:** SECURITY_AUDIT_REPORT.md

---

## ⚠️ DÔLEŽITÉ: GitHub Pages obmedzenia

GitHub Pages je **statický hosting** bez možnosti konfigurácie server-side nastavení. To znamená, že **niektoré odporúčania z hlavného auditu nie je možné implementovať** bez migrácie na iný hosting.

---

## 🚫 ČO NIE JE MOŽNÉ NA GITHUB PAGES

### 1. HTTP Security Headers (HIGH-03 z auditu)

**NEFUNGUJE na GitHub Pages:**
```nginx
# ❌ Tieto headers nemožno nastaviť na GitHub Pages
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
Permissions-Policy: geolocation=()
```

**Dôvod:** GitHub Pages nepodporuje custom HTTP headers. Môžete použiť **iba meta tagy** v HTML.

**Čo UŽ MÁTE (funguje):**
```html
<!-- ✅ Tieto meta tagy fungujú -->
<meta http-equiv="Content-Security-Policy" content="...">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta name="referrer" content="no-referrer">
```

**Čo NEFUNGUJE cez meta tagy:**
- ❌ `Strict-Transport-Security` (HSTS) - musí byť HTTP header
- ❌ `X-Frame-Options` - musí byť HTTP header (použite CSP `frame-ancestors`)
- ❌ `Permissions-Policy` - musí byť HTTP header
- ⚠️ `Content-Security-Policy: frame-ancestors` - iba cez HTTP header

**Workaround:**
```html
<!-- Pridajte do index.html pre čiastočnú clickjacking ochranu -->
<script>
  // Ochrana proti frame embedding (clickjacking)
  if (window.self !== window.top) {
    window.top.location = window.self.location;
  }
</script>
```

---

### 2. Server-side konfigurácia

**NEFUNGUJE:**
- ❌ `.htaccess` (Apache)
- ❌ `nginx.conf` (Nginx)
- ❌ `firebase.json` hosting config
- ❌ Custom redirects/rewrites
- ❌ Rate limiting na server-side
- ❌ IP blokovanie

---

## ✅ ČO JE APLIKOVATEĽNÉ NA GITHUB PAGES

### KRITICKÉ priority (implementujte):

#### 🔴 CRITICAL-01: Firebase Security Rules ✅
**Aplikovateľné:** ÁNO
**Nezávisí od hostingu**

```javascript
// Vytvorte firestore.rules v projekte
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/calculatorData/{document=**} {
      allow read, write: if request.auth != null
                         && request.auth.uid == userId;
    }
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

**Nasadenie:**
```bash
# Install Firebase CLI
npm install -g firebase-tools

# Login
firebase login

# Deploy rules
firebase deploy --only firestore:rules
```

---

#### 🔴 CRITICAL-02: jsPDF XSS (CVE-2020-7691) ✅
**Aplikovateľné:** ÁNO
**Nezávisí od hostingu**

**Aktualizujte v index.html:**
```html
<!-- Zmeňte z v2.5.1 na v2.5.2 alebo vyššie -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.2/jspdf.umd.min.js"
        integrity="sha512-[NOVÝ-SRI-HASH]"
        crossorigin="anonymous"></script>
```

**A pridajte sanitizáciu v app.js:**
```javascript
function sanitizeForPDF(text) {
  if (!text) return '';
  return text
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// V exportToPDF() a sendPDF()
const noteText = sanitizeForPDF(day.note || '');
```

---

#### 🔴 CRITICAL-03: API kľúče ⚠️
**Aplikovateľné:** ČIASTOČNE
**Firebase API kľúče sú navrhnuté ako verejné pre client-side apps**

**Čo UROBIŤ:**

1. **Firebase Console - Application restrictions:**
   - Choďte do Firebase Console → Project Settings → General
   - V sekcii "Your apps" → Web app → App check
   - Povoľte iba vašu GitHub Pages doménu:
     ```
     https://[username].github.io
     ```

2. **Firebase Console - API restrictions:**
   - Google Cloud Console → APIs & Services → Credentials
   - Nájdite "Browser key (auto created by Firebase)"
   - Application restrictions → HTTP referrers
   - Pridajte:
     ```
     https://[username].github.io/*
     ```

3. **Overte App Check je aktívny** (už máte v app.js):
   ```javascript
   firebase.appCheck().activate('6LcagP8qAAAAA...', true); // ✅ OK
   ```

---

### VYSOKÉ priority (implementujte):

#### 🟠 HIGH-01: localStorage šifrovanie ✅
**Aplikovateľné:** ÁNO

```javascript
// Pridajte na začiatok app.js
class StorageEncryption {
  async init() {
    const user = auth.currentUser;
    if (!user) return null;

    // Použiť UID ako seed pre kľúč
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(user.uid + 'bruno-calc-salt-v1'),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    this.key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('static-salt-change-in-production'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    return this.key;
  }

  async encrypt(data) {
    if (!this.key) await this.init();
    if (!this.key) return data; // Fallback ak nie je user

    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(data));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.key,
      encodedData
    );

    return JSON.stringify({
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(encryptedData))
    });
  }

  async decrypt(encryptedString) {
    if (!this.key) await this.init();
    if (!this.key) return JSON.parse(encryptedString); // Fallback

    try {
      const encrypted = JSON.parse(encryptedString);
      const decryptedData = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
        this.key,
        new Uint8Array(encrypted.data)
      );

      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decryptedData));
    } catch (e) {
      // Ak dešifrovanie zlyhá, vráť plain data (pre backward compatibility)
      return JSON.parse(encryptedString);
    }
  }
}

const storageEncryption = new StorageEncryption();

// Upravte saveToLocalStorage()
async function saveToLocalStorage(skipFirebaseSync = false) {
  const serializedMonthData = JSON.stringify(monthData);

  // Encrypt pred uložením
  const encrypted = await storageEncryption.encrypt(monthData);
  localStorage.setItem('workDaysData', encrypted);

  // ... zvyšok kódu
}

// Upravte loadFromLocalStorage()
async function loadFromLocalStorage() {
  const storedData = localStorage.getItem('workDaysData');
  if (!storedData) return;

  try {
    monthData = await storageEncryption.decrypt(storedData);
  } catch (error) {
    console.error('Chyba pri dekryptovaní dát:', error);
    monthData = {};
  }

  // ... zvyšok kódu
}
```

---

#### 🟠 HIGH-02: Šifrovanie backupov ✅
**Aplikovateľné:** ÁNO

```javascript
async function createEncryptedBackup() {
  const password = prompt(
    'Zadajte heslo pre šifrovanie zálohy (min 12 znakov):\n\n' +
    '⚠️ UPOZORNENIE: Bez tohto hesla nebude možné obnoviť zálohu!'
  );

  if (!password || password.length < 12) {
    alert('Heslo musí mať aspoň 12 znakov.');
    return;
  }

  try {
    const backupData = {
      workDaysData: localStorage.getItem('workDaysData') || '{}',
      hourlyWage: localStorage.getItem('hourlyWage') || '10',
      taxRate: localStorage.getItem('taxRate') || '2',
      employeeName: localStorage.getItem('employeeName') || '""',
      decimalPlaces: localStorage.getItem('decimalPlaces') || '1',
      darkMode: localStorage.getItem('darkMode') || 'false',
      backupVersion: 3, // Zvýšené pre encrypted version
      backupTimestamp: new Date().toISOString()
    };

    // Encrypt s heslom
    const encrypted = await encryptWithPassword(JSON.stringify(backupData), password);

    const blob = new Blob([JSON.stringify(encrypted)], {
      type: "application/json;charset=utf-8"
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bruno-backup-encrypted-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showSaveNotification("Šifrovaná záloha vytvorená.");
  } catch (error) {
    console.error("Chyba pri vytváraní zálohy:", error);
    alert("Nastala chyba pri vytváraní zálohy.");
  }
}

async function encryptWithPassword(data, password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  );

  return {
    encrypted: true,
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(encryptedData))
  };
}
```

---

#### 🟠 HIGH-05: Production logging ✅
**Aplikovateľné:** ÁNO

```javascript
// Pridajte na začiatok app.js
const IS_PRODUCTION = window.location.hostname.includes('github.io');

const logger = {
  log: (...args) => {
    if (!IS_PRODUCTION) console.log(...args);
  },
  warn: (...args) => {
    if (!IS_PRODUCTION) console.warn(...args);
  },
  error: (msg, error) => {
    if (!IS_PRODUCTION) {
      console.error(msg, error);
    } else {
      // V produkcii loguj len error code
      console.error(msg, error?.code || 'unknown');
    }
  }
};

// Nahraďte všetky console.log/warn/error s logger.log/warn/error
// Príklad:
// console.log('test') → logger.log('test')
// console.error('err', e) → logger.error('err', e)
```

---

## 🔄 ALTERNATÍVNE RIEŠENIA PRE GITHUB PAGES

### Clickjacking ochrana (namiesto X-Frame-Options)

```html
<!-- Pridajte do <head> v index.html -->
<style>
  /* Framebuster pre staré browsery */
  html { display: none; }
</style>
<script>
  // Anti-framejacking
  if (self === top) {
    document.documentElement.style.display = 'block';
  } else {
    top.location = self.location;
  }
</script>
```

### CSP frame-ancestors workaround

```html
<!-- V index.html CSP pridajte (aj keď bude ignorované v meta tag): -->
<!-- Aspoň dokumentuje intent -->
<!-- Content-Security-Policy: frame-ancestors 'none' -->
```

### HTTPS enforcement

GitHub Pages **automaticky vynucuje HTTPS** pre `*.github.io` domény:
- ✅ HTTPS je vždy aktívne
- ✅ HTTP→HTTPS redirect funguje
- ❌ Nemôžete nastaviť HSTS header (ale nie je kriticky potrebný)

---

## 🚀 ODPORÚČANIE: Zostať na GitHub Pages alebo migrovať?

### ✅ ZOSTAŤ NA GITHUB PAGES AK:
- Aplikácia je primárne pre osobné použitie
- Nepotrebujete advanced security features
- Chcete jednoduchý deployment
- **Implementujete všetky aplikovateľné fixes z auditu**

### 🔄 MIGROVAŤ NA FIREBASE HOSTING AK:
- Potrebujete plnú kontrolu nad HTTP headers
- Chcete najlepšiu možnú bezpečnosť
- Potrebujete custom redirects/rewrites
- Chcete lepšiu integráciu s Firebase službami

**Firebase Hosting setup:**
```bash
# Install Firebase CLI
npm install -g firebase-tools

# Initialize
firebase init hosting

# firebase.json
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
            "value": "geolocation=(), camera=(), microphone=()"
          },
          {
            "key": "Referrer-Policy",
            "value": "no-referrer"
          }
        ]
      }
    ],
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ]
  }
}

# Deploy
firebase deploy --only hosting
```

**Náklady:** Firebase Hosting má **generous free tier**:
- 10 GB storage
- 360 MB/day bandwidth
- Pre malú aplikáciu je to **zadarmo**

---

## 📋 AKTUALIZOVANÝ CHECKLIST PRE GITHUB PAGES

### KRITICKÉ (urobiť TERAZ):
- [ ] Vytvoriť a nasadiť `firestore.rules`
- [ ] Pridať domain restriction v Firebase Console
- [ ] Upgrade jsPDF na v2.5.2+
- [ ] Implementovať PDF sanitizáciu
- [ ] Implementovať localStorage encryption

### VYSOKÉ (urobiť tento týždeň):
- [ ] Implementovať šifrovanie backupov
- [ ] Nahradiť console.* s logger.*
- [ ] Pridať anti-framejacking script
- [ ] Zlepšiť password policy (min 12 znakov)

### STREDNÉ (urobiť tento mesiac):
- [ ] Client-side rate limiting
- [ ] Backup validation improvements
- [ ] CSP optimalizácia (zúžiť img-src)

### VOLITEĽNÉ:
- [ ] Zvážiť migráciu na Firebase Hosting
- [ ] Self-host fonty
- [ ] Automated cache versioning

---

## 🎯 UPRAVENÉ BEZPEČNOSTNÉ SKÓRE

S GitHub Pages obmedzeniami:

**Pred opravami:** 47% (18/38)
**Po aplikovateľných opravách:** ~75% (28/38) 🟢
**S migráciou na Firebase Hosting:** ~92% (35/38) ✅

---

## 📞 ZÁVER

Pre **GitHub Pages hosting**, hlavný bezpečnostný audit zostává platný, ale:

✅ **Aplikovateľné (priorita):**
- Firebase Security Rules
- jsPDF upgrade + sanitizácia
- localStorage šifrovanie
- Backup šifrovanie
- Production logging cleanup
- Password policy improvements

❌ **Nie je možné bez migrácie:**
- HTTP security headers (HSTS, X-Frame-Options, Permissions-Policy)
- Server-side rate limiting
- Custom redirects

⚠️ **Workaround existuje:**
- Anti-framejacking cez JavaScript
- CSP cez meta tagy (už máte)
- GitHub Pages auto HTTPS

**Odporúčanie:** Implementujte všetky aplikovateľné fixes. GitHub Pages je **dostatočne bezpečný** pre túto aplikáciu ak opravíte CRITICAL a HIGH priority problémy.

Ak potrebujete maximálnu bezpečnosť, zvážte **Firebase Hosting** (zadarmo pre malé projekty, 10 minút setup).
