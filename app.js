// =========================
// Bruno Calc Pro+ (merged "super" version)
// =========================

// ---- Firebase imports (ESM) ----
import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-app.js';
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  sendPasswordResetEmail
} from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js';

import {
  initializeFirestore,
  persistentLocalCache,
  CACHE_SIZE_UNLIMITED,
  doc,
  setDoc,
  getDoc,
  onSnapshot,
  writeBatch,
  serverTimestamp
} from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js';

import { initializeAppCheck, ReCaptchaV3Provider } from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-app-check.js';

// ---- CONFIG (replace for production) ----
const firebaseConfig = {
  apiKey: "AIzaSyBdLtJlduT3iKiGLDJ0UfAakpf6wcresnk",
  authDomain: "uuuuu-f7ef9.firebaseapp.com",
  projectId: "uuuuu-f7ef9",
  storageBucket: "uuuuu-f7ef9.appspot.com",
  messagingSenderId: "456105865458",
  appId: "1:456105865458:web:101f0a4dcb455f174b606b",
};

const RECAPTCHA_V3_SITE_KEY = "6LczmP0qAAAAAACGalBT9zZekkUr3hLgA2e8o99v";

// =========================
// Helpers / Security utils
// =========================

const TEXT_LIMITS = {
  projectTag: 200,
  note: 2000,
  employeeName: 100,
  time: 5,
  breakTime: 10
};

function sanitizeText(text, maxLength) {
  if (typeof text !== 'string') return '';
  return text.trim().substring(0, maxLength);
}

function safeJsonParse(jsonString, fallback = null) {
  if (!jsonString || typeof jsonString !== 'string') return fallback;
  try { return JSON.parse(jsonString); }
  catch { return fallback; }
}

// basic email validation
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim()) && email.length <= 320;
}

// Rate limiting (anti-spam click)
const rateLimitedButtons = new Map();
function isRateLimited(key, cooldownMs = 2000) {
  const now = Date.now();
  const last = rateLimitedButtons.get(key);
  if (last && (now - last) < cooldownMs) return true;
  rateLimitedButtons.set(key, now);
  return false;
}

// Safe logging (no secrets)
function secureLog(level, message) {
  const msg = typeof message === 'string' ? message : 'Unknown';
  if (level === 'error') console.error(msg);
  else if (level === 'warn') console.warn(msg);
  else console.log(msg);
}

// Timeout helper
function withTimeout(promise, timeoutMs = 10000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Operation timeout')), timeoutMs))
  ]);
}

// =========================
// UI helpers
// =========================

function $(id) { return document.getElementById(id); }
function firstEl(...ids) { return ids.map($).find(Boolean) || null; }

function showNotification(id, message, duration = 3500) {
  const el = $(id);
  if (!el) return;
  el.textContent = String(message ?? '');
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), duration);
}
function showSaveNotification(message = 'Dáta boli úspešne uložené.') {
  showNotification('saveNotification', message, 3500);
}
function showErrorNotification(message = 'Nastala chyba.') {
  showNotification('errorNotification', message, 5000);
}
function showWarningNotification(message = 'Upozornenie.') {
  showNotification('warningNotification', message, 4500);
}

function setLoadingState(button, isLoading, textParam = "Spracúvam...") {
  if (!button) return;
  if (isLoading) {
    button.disabled = true;
    if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
    const spinnerSpan = document.createElement('span');
    spinnerSpan.className = 'spinner';
    spinnerSpan.setAttribute('role', 'status');
    spinnerSpan.setAttribute('aria-hidden', 'true');
    button.textContent = '';
    button.appendChild(spinnerSpan);
    button.appendChild(document.createTextNode(` ${textParam}`));
    button.classList.add('is-loading');
  } else {
    button.disabled = false;
    button.textContent = button.dataset.originalText || button.textContent;
    delete button.dataset.originalText;
    button.classList.remove('is-loading');
  }
}

// =========================
// App State
// =========================

const MONTH_NAMES = ["Január","Február","Marec","Apríl","Máj","Jún","Júl","August","September","Október","November","December"];
const DAY_NAMES_SHORT = ["Ne","Po","Ut","St","Št","Pi","So"];

const PENDING_SYNC_MONTHS_LS_KEY = 'pendingSyncMonthsList';

const currentDate = new Date();
let currentMonth = currentDate.getMonth();
let currentYear = currentDate.getFullYear();

let appSettings = {
  decimalPlaces: 2,
  employeeName: '',
  hourlyWage: 10,
  taxRate: 0.02,
  theme: 'light',
  monthlyEarningsGoal: null
};

let currentUser = null;
let currentListenerUnsubscribe = null;
let didLoadSettingsFromFirestore = false;
let appSettingsDirty = false;

// editing / conflict protection
let isUserEditing = false;
let userEditingTimeout = null;
let conflictCheckInProgress = false;
let lastConflictKey = null;
let snapshotSeq = 0;

function setUserEditing() {
  isUserEditing = true;
  if (userEditingTimeout) clearTimeout(userEditingTimeout);
  userEditingTimeout = setTimeout(() => { isUserEditing = false; }, 2000);
}

// =========================
// Firebase init
// =========================

const app = initializeApp(firebaseConfig);

try {
  initializeAppCheck(app, {
    provider: new ReCaptchaV3Provider(RECAPTCHA_V3_SITE_KEY),
    isTokenAutoRefreshEnabled: true
  });
} catch (e) {
  secureLog('warn', 'App Check initialization failed.');
  showWarningNotification("Inicializácia App Check zlyhala. Niektoré funkcie môžu byť obmedzené.");
}

const auth = getAuth(app);

let db;
try {
  db = initializeFirestore(app, {
    localCache: persistentLocalCache({ sizeBytes: CACHE_SIZE_UNLIMITED })
  });
} catch (e) {
  secureLog('warn', 'Failed to init Firestore persistent cache, fallback to memory.');
  showWarningNotification("Chyba pri inicializácii offline úložiska. Dáta nebudú dostupné offline.");
  db = initializeFirestore(app, {});
}

// =========================
// UI refs (supports both ID variants)
// =========================

const uiRefs = {
  workDaysTbody: firstEl('workDays'),
  totalSalaryDiv: firstEl('totalSalary'),
  mainTitle: firstEl('mainTitle'),
  subTitle: firstEl('subTitle'),
  hourlyWageInput: firstEl('hourlyWageInput'),
  taxRateInput: firstEl('taxRateInput'),
  monthSelect: firstEl('monthSelect'),
  yearSelect: firstEl('yearSelect'),
  decimalPlacesSelect: firstEl('decimalPlacesSelect'),
  employeeNameInput: firstEl('employeeNameInput'),

  themeToggleBtn: firstEl('themeToggleBtn'),
  themeIcon: firstEl('themeIcon'),
  themeMeta: document.querySelector('meta[name="theme-color"]'),

  loginFieldset: firstEl('login-fieldset'),
  userInfo: firstEl('user-info'),
  userEmailSpan: firstEl('user-email'),
  appLoader: firstEl('app-loader'),
  mainContainer: document.querySelector('.container'),

  // auth button ids variants
  loginBtn: firstEl('loginBtn', 'btnLogin'),
  registerBtn: firstEl('registerBtn', 'btnRegister'),
  resetPasswordLink: firstEl('resetPasswordLink', 'linkResetPassword'),
  logoutBtn: firstEl('logoutBtn', 'btnLogout'),

  // other buttons ids variants (optional)
  exportPdfBtn: firstEl('exportPdfBtn', 'btnExportPdf'),
  sendPdfBtn: firstEl('sendPdfBtn', 'btnSendPdf'),
  createBackupBtn: firstEl('createBackupBtn', 'btnCreateBackup'),
  restoreBackupBtn: firstEl('restoreBackupBtn', 'btnRestoreBackup'),
  clearMonthBtn: firstEl('clearMonthBtn', 'btnClearMonth'),

  toggleSettingsBtn: firstEl('toggleSettingsBtn'),
};

// =========================
// Theme Manager
// =========================

const ThemeManager = {
  init() {
    const storedTheme = localStorage.getItem('theme');
    if (storedTheme) appSettings.theme = storedTheme;
    else {
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      appSettings.theme = prefersDark ? 'dark' : 'light';
    }
    this.applyTheme(appSettings.theme);

    if (uiRefs.themeToggleBtn) {
      uiRefs.themeToggleBtn.addEventListener('click', () => this.toggleTheme());
    }
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        if (!localStorage.getItem('theme')) {
          appSettings.theme = e.matches ? 'dark' : 'light';
          this.applyTheme(appSettings.theme);
        }
      });
    }
  },
  applyTheme(theme) {
    const t = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', t);
    if (uiRefs.themeIcon) uiRefs.themeIcon.textContent = t === 'dark' ? '☀️' : '🌙';
    appSettings.theme = t;
    localStorage.setItem('theme', t);
    if (uiRefs.themeMeta) {
      uiRefs.themeMeta.content = getComputedStyle(document.documentElement)
        .getPropertyValue('--theme-color-meta')
        .trim();
    }
  },
  toggleTheme() {
    const next = appSettings.theme === 'light' ? 'dark' : 'light';
    this.applyTheme(next);
    saveAppSettingToLocalStorage('theme', next);
    debouncedSaveAppSettingsToFirestore();
  }
};

// =========================
// App badge + pending sync list
// =========================

async function updateAppBadge(count) {
  if (!('setAppBadge' in navigator)) return;
  try {
    if (count > 0) await navigator.setAppBadge(count);
    else await navigator.clearAppBadge();
  } catch { /* ignore */ }
}

function getPendingSyncMonths() {
  return safeJsonParse(localStorage.getItem(PENDING_SYNC_MONTHS_LS_KEY), []);
}
function savePendingSyncMonths(months) {
  localStorage.setItem(PENDING_SYNC_MONTHS_LS_KEY, JSON.stringify(months));
  updateAppBadge(months.length);
}
function addMonthToPendingList(docId) {
  if (!currentUser) return;
  const list = getPendingSyncMonths();
  if (!list.includes(docId)) {
    list.push(docId);
    savePendingSyncMonths(list);
  }
}
function removeMonthFromPendingList(docId) {
  const list = getPendingSyncMonths().filter(x => x !== docId);
  savePendingSyncMonths(list);
}
function getPendingSyncCount() {
  if (!currentUser) return 0;
  return getPendingSyncMonths().length;
}

// =========================
// Time/date helpers
// =========================

function getDaysInMonth(month, year) { return new Date(year, month + 1, 0).getDate(); }
function getDayName(year, month, day) { return DAY_NAMES_SHORT[new Date(year, month, day).getDay()]; }
function isWeekend(year, month, day) { const d = new Date(year, month, day).getDay(); return d === 0 || d === 6; }
function getFirestoreDocId(year, month) { return `${year}-${String(month + 1).padStart(2, '0')}`; }
function getLocalStorageKeyForWorkData(docId) { return currentUser ? `workData-${currentUser.uid}-${docId}` : `workData-guest-${docId}`; }
function getPendingSyncKeyForMonth(docId) { return currentUser ? `pendingSync-workData-${currentUser.uid}-${docId}` : null; }

function isValidTimeFormat(timeString) {
  return typeof timeString === 'string' && /^([01]\d|2[0-3]):([0-5]\d)$/.test(timeString);
}

function formatTimeInputOnly(input) {
  const raw = String(input.value ?? '');
  const cursorPos = input.selectionStart ?? raw.length;

  let digits = raw.replace(/[^\d]/g, '').slice(0, 4);
  let formatted = digits;
  if (digits.length >= 3) formatted = `${digits.slice(0, 2)}:${digits.slice(2)}`;
  else if (digits.length >= 2 && raw.includes(':')) formatted = `${digits.slice(0, 2)}:${digits.slice(2)}`;

  const hadColon = raw.includes(':');
  const willHaveColon = formatted.includes(':');
  const colonAdded = !hadColon && willHaveColon;

  input.value = formatted;

  // try restore cursor
  let newPos = cursorPos;
  if (colonAdded && cursorPos >= 2) newPos = cursorPos + 1;
  newPos = Math.min(newPos, formatted.length);
  try { input.setSelectionRange(newPos, newPos); } catch { /* ignore */ }
}

// =========================
// Debounce
// =========================

function debounce(fn, wait) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
}

// =========================
// Settings storage
// =========================

function loadAppSettingsFromLocalStorage() {
  appSettings.decimalPlaces = parseInt(localStorage.getItem('decimalPlaces')) || 2;
  appSettings.employeeName = localStorage.getItem('employeeName') || '';
  appSettings.hourlyWage = parseFloat(localStorage.getItem('hourlyWage')) || 10;
  appSettings.taxRate = parseFloat(localStorage.getItem('taxRate')) || 0.02;
  appSettings.theme = localStorage.getItem('theme') || appSettings.theme || 'light';
  appSettings.monthlyEarningsGoal = localStorage.getItem('monthlyEarningsGoal')
    ? parseFloat(localStorage.getItem('monthlyEarningsGoal'))
    : null;
}

function saveAppSettingToLocalStorage(key, value) {
  localStorage.setItem(key, String(value));
  appSettings[key] = value;
  appSettingsDirty = true;
}

function sanitizeSettingsForFirestore() {
  return {
    decimalPlaces: Number.isFinite(appSettings.decimalPlaces) ? Math.floor(appSettings.decimalPlaces) : 2,
    employeeName: sanitizeText(String(appSettings.employeeName || ''), TEXT_LIMITS.employeeName),
    hourlyWage: Number.isFinite(appSettings.hourlyWage) ? appSettings.hourlyWage : 0,
    taxRate: Number.isFinite(appSettings.taxRate) ? appSettings.taxRate : 0,
    theme: appSettings.theme === 'dark' ? 'dark' : 'light',
    monthlyEarningsGoal: Number.isFinite(appSettings.monthlyEarningsGoal) ? appSettings.monthlyEarningsGoal : null
  };
}

async function saveAppSettingsToFirestore() {
  if (!currentUser || !navigator.onLine) return;
  const userDocRef = doc(db, 'users', currentUser.uid);
  const sanitizedSettings = sanitizeSettingsForFirestore();

  try {
    const snap = await withTimeout(getDoc(userDocRef), 8000);
    if (snap.exists()) {
      await withTimeout(setDoc(userDocRef, { email: currentUser.email, appSettings: sanitizedSettings }, { merge: true }), 8000);
    } else {
      await withTimeout(setDoc(userDocRef, { email: currentUser.email, createdAt: serverTimestamp(), appSettings: sanitizedSettings }), 8000);
    }
    appSettingsDirty = false;
  } catch (e) {
    secureLog('error', 'Error saving app settings to Firestore');
    showErrorNotification('Nepodarilo sa uložiť nastavenia aplikácie do cloudu.');
  }
}
const debouncedSaveAppSettingsToFirestore = debounce(saveAppSettingsToFirestore, 1800);

async function loadUserAppSettingsFromFirestore() {
  if (!currentUser || !navigator.onLine) return false;
  const userDocRef = doc(db, 'users', currentUser.uid);

  try {
    const snap = await withTimeout(getDoc(userDocRef), 8000);
    if (snap.exists() && snap.data()?.appSettings) {
      const fs = snap.data().appSettings;
      // merge with type normalization
      if (fs.decimalPlaces != null) appSettings.decimalPlaces = parseInt(fs.decimalPlaces) || 2;
      if (fs.employeeName != null) appSettings.employeeName = String(fs.employeeName);
      if (fs.hourlyWage != null) appSettings.hourlyWage = parseFloat(fs.hourlyWage) || 0;
      if (fs.taxRate != null) appSettings.taxRate = parseFloat(fs.taxRate) || 0;
      if (fs.theme === 'dark' || fs.theme === 'light') appSettings.theme = fs.theme;
      if (fs.monthlyEarningsGoal != null) {
        const v = parseFloat(fs.monthlyEarningsGoal);
        appSettings.monthlyEarningsGoal = Number.isFinite(v) ? v : null;
      }

      // persist local
      localStorage.setItem('decimalPlaces', String(appSettings.decimalPlaces));
      localStorage.setItem('employeeName', String(appSettings.employeeName));
      localStorage.setItem('hourlyWage', String(appSettings.hourlyWage));
      localStorage.setItem('taxRate', String(appSettings.taxRate));
      localStorage.setItem('theme', String(appSettings.theme));
      if (appSettings.monthlyEarningsGoal == null) localStorage.removeItem('monthlyEarningsGoal');
      else localStorage.setItem('monthlyEarningsGoal', String(appSettings.monthlyEarningsGoal));

      didLoadSettingsFromFirestore = true;
      return true;
    }
    didLoadSettingsFromFirestore = true;
  } catch (e) {
    secureLog('error', 'Error loading app settings from Firestore');
    showErrorNotification('Chyba načítania nastavení aplikácie z cloudu.');
  }
  return false;
}

function updateSettingsUIInputs() {
  if (uiRefs.decimalPlacesSelect) uiRefs.decimalPlacesSelect.value = String(appSettings.decimalPlaces);
  if (uiRefs.employeeNameInput) uiRefs.employeeNameInput.value = appSettings.employeeName;

  if (uiRefs.hourlyWageInput) {
    const wage = Number.isFinite(appSettings.hourlyWage) ? appSettings.hourlyWage : 0;
    uiRefs.hourlyWageInput.value = wage.toFixed(appSettings.decimalPlaces > 0 ? appSettings.decimalPlaces : 1);
  }
  if (uiRefs.taxRateInput) {
    const tax = Number.isFinite(appSettings.taxRate) ? appSettings.taxRate : 0;
    uiRefs.taxRateInput.value = (tax * 100).toFixed(1);
  }
}

// =========================
// Auth
// =========================

const authErrorMap = {
  'auth/invalid-email': 'Neplatný formát emailu.',
  'auth/user-disabled': 'Tento účet bol deaktivovaný.',
  'auth/user-not-found': 'Používateľ s týmto emailom nebol nájdený.',
  'auth/wrong-password': 'Nesprávne heslo.',
  'auth/email-already-in-use': 'Tento email je už zaregistrovaný.',
  'auth/weak-password': 'Heslo je príliš slabé (min. 6 znakov).',
  'auth/requires-recent-login': 'Vyžaduje sa nedávne prihlásenie. Odhláste sa a prihláste znova.',
  'auth/network-request-failed': 'Chyba sieťového pripojenia.',
  'auth/too-many-requests': 'Príliš veľa pokusov. Skúste neskôr.',
  'auth/missing-email': 'Prosím, zadajte emailovú adresu.',
};
function mapFirebaseAuthError(code) {
  return authErrorMap[code] || `Neznáma chyba (${code}).`;
}

async function loginUser(e) {
  const btn = e?.currentTarget || uiRefs.loginBtn;
  if (!btn || isRateLimited('login', 3000)) return;

  setLoadingState(btn, true, "Prihlasujem...");
  try {
    if (!navigator.onLine) throw new Error('offline');
    const email = String($('email')?.value || '').trim();
    const password = String($('password')?.value || '');

    if (!email || !password) { showErrorNotification('Prosím, zadajte email aj heslo.'); return; }
    if (!isValidEmail(email)) { showErrorNotification('Prosím, zadajte platnú emailovú adresu.'); return; }

    await signInWithEmailAndPassword(auth, email, password);
    showSaveNotification('Úspešne prihlásený.');
  } catch (err) {
    if (err?.message === 'offline') showErrorNotification('Ste offline. Prihlásenie je možné iba online.');
    else showErrorNotification('Chyba pri prihlásení: ' + mapFirebaseAuthError(err?.code));
  } finally {
    setLoadingState(btn, false, "Prihlásiť sa");
  }
}

async function registerUser(e) {
  const btn = e?.currentTarget || uiRefs.registerBtn;
  if (!btn || isRateLimited('register', 3000)) return;

  setLoadingState(btn, true, "Registrujem...");
  try {
    if (!navigator.onLine) throw new Error('offline');
    const email = String($('email')?.value || '').trim();
    const password = String($('password')?.value || '');

    if (!email || !password) { showErrorNotification('Prosím, zadajte email aj heslo.'); return; }
    if (!isValidEmail(email)) { showErrorNotification('Prosím, zadajte platnú emailovú adresu.'); return; }
    if (password.length < 6) { showErrorNotification('Heslo musí mať aspoň 6 znakov.'); return; }

    await createUserWithEmailAndPassword(auth, email, password);
    await createUserCollectionAndSettings();
    showSaveNotification('Úspešne zaregistrovaný a prihlásený.');
  } catch (err) {
    if (err?.message === 'offline') showErrorNotification('Ste offline. Registrácia je možná iba online.');
    else showErrorNotification('Chyba pri registrácii: ' + mapFirebaseAuthError(err?.code));
  } finally {
    setLoadingState(btn, false, "Registrovať");
  }
}

async function createUserCollectionAndSettings() {
  if (!auth.currentUser) return;
  const uid = auth.currentUser.uid;

  const userDocRef = doc(db, 'users', uid);
  const initialMonthDocId = getFirestoreDocId(currentYear, currentMonth);
  const initialMonthDocRef = doc(db, 'users', uid, 'workData', initialMonthDocId);

  const batch = writeBatch(db);
  batch.set(userDocRef, {
    email: auth.currentUser.email,
    createdAt: serverTimestamp(),
    appSettings: sanitizeSettingsForFirestore()
  }, { merge: true });

  batch.set(initialMonthDocRef, { data: [], lastUpdated: serverTimestamp() }, { merge: true });

  try {
    await batch.commit();
  } catch (e) {
    secureLog('error', 'Error creating user collection/settings');
    showErrorNotification('Nepodarilo sa inicializovať používateľské dáta v cloude.');
  }
}

async function logoutUser(e) {
  const btn = e?.currentTarget || uiRefs.logoutBtn;
  if (!btn || isRateLimited('logout', 2000)) return;

  setLoadingState(btn, true, "Odhlasujem...");
  try {
    if (currentListenerUnsubscribe) { currentListenerUnsubscribe(); currentListenerUnsubscribe = null; }
    await signOut(auth);
    showSaveNotification('Úspešne odhlásený.');
  } catch (err) {
    showErrorNotification('Chyba pri odhlásení.');
  } finally {
    setLoadingState(btn, false, "Odhlásiť sa");
  }
}

async function resetUserPassword() {
  if (isRateLimited('resetPassword', 5000)) {
    showWarningNotification('Počkajte prosím pred ďalším pokusom.');
    return;
  }
  if (!navigator.onLine) { showErrorNotification('Ste offline. Obnova hesla je možná iba online.'); return; }

  const emailInput = $('email');
  const email = String(emailInput?.value || '').trim();
  if (!email) { showErrorNotification('Zadajte email pre obnovu hesla.'); return; }
  if (!isValidEmail(email)) { showErrorNotification('Zadajte platný email.'); return; }

  try {
    await sendPasswordResetEmail(auth, email);
    showSaveNotification(`Email na obnovu hesla bol odoslaný na adresu ${email}.`);
  } catch (err) {
    showErrorNotification('Chyba pri odosielaní emailu: ' + mapFirebaseAuthError(err?.code));
  }
}

function updateUIForAuthStateChange() {
  const isLoggedIn = !!currentUser;

  if (uiRefs.loginFieldset) {
    // podporuje obidva spôsoby: class "hidden" alebo display
    uiRefs.loginFieldset.classList.toggle('hidden', isLoggedIn);
    uiRefs.loginFieldset.style.display = isLoggedIn ? 'none' : '';
  }

  if (uiRefs.userInfo) {
    uiRefs.userInfo.classList.toggle('hidden', !isLoggedIn);
    uiRefs.userInfo.style.display = isLoggedIn ? 'flex' : '';
  }

  if (isLoggedIn && uiRefs.userEmailSpan) uiRefs.userEmailSpan.textContent = `Prihlásený: ${currentUser.email}`;
  updateAppBadge(getPendingSyncCount());
}

// =========================
// Work data: collect + save + sync
// =========================

function collectWorkDataForStorage() {
  const days = getDaysInMonth(currentMonth, currentYear);
  const data = [];

  for (let i = 1; i <= days; i++) {
    data.push({
      start: sanitizeText(String($(`start-${i}`)?.value || ''), TEXT_LIMITS.time),
      end: sanitizeText(String($(`end-${i}`)?.value || ''), TEXT_LIMITS.time),
      breakTime: sanitizeText(String($(`break-${i}`)?.value || ''), TEXT_LIMITS.breakTime),
      projectTag: sanitizeText(String($(`project-${i}`)?.value || ''), TEXT_LIMITS.projectTag),
      note: sanitizeText(String($(`note-${i}`)?.value || ''), TEXT_LIMITS.note),
    });
  }

  return { data, lastUpdated: new Date().toISOString() };
}

async function saveWorkDataToFirestore(dataToSave, docId) {
  if (!currentUser) throw new Error("User not logged in.");
  if (!navigator.onLine) throw new Error("Cannot save: offline.");

  const docRef = doc(db, 'users', currentUser.uid, 'workData', docId);

  // sanitize for Firestore rules (safer than raw)
  const sanitizedData = (dataToSave?.data || []).map(day => {
    const start = sanitizeText(String(day?.start || ''), TEXT_LIMITS.time).slice(0, 5);
    const end = sanitizeText(String(day?.end || ''), TEXT_LIMITS.time).slice(0, 5);

    let breakTime = null;
    if (day?.breakTime !== '' && day?.breakTime != null) {
      const parsed = parseFloat(String(day.breakTime).replace(',', '.'));
      if (Number.isFinite(parsed)) breakTime = Math.max(0, Math.min(24, parsed));
    }

    const projectTag = sanitizeText(String(day?.projectTag || ''), TEXT_LIMITS.projectTag);
    const note = sanitizeText(String(day?.note || ''), TEXT_LIMITS.note);

    return { start, end, breakTime, projectTag, note };
  });

  const firestoreData = { data: sanitizedData, lastUpdated: serverTimestamp() };

  await withTimeout(setDoc(docRef, firestoreData, { merge: true }), 10000);
}

function updateLocalStorageSizeIndicator() {
  const el = uiRefs.localStorageIndicator;
  if (!el) return;
  let total = 0;
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    total += (k.length + (localStorage.getItem(k)?.length || 0)) * 2;
  }
  el.textContent = `Lokálne uložené: ~${(total / 1024).toFixed(1)}KB`;
}

const debouncedSaveWorkDataAndSync = debounce(async () => {
  const dataToSave = collectWorkDataForStorage();
  const docId = getFirestoreDocId(currentYear, currentMonth);
  const localKey = getLocalStorageKeyForWorkData(docId);
  const dataStr = JSON.stringify(dataToSave);

  localStorage.setItem(localKey, dataStr);
  updateLocalStorageSizeIndicator();

  if (currentUser) {
    const pendingKey = getPendingSyncKeyForMonth(docId);
    if (navigator.onLine) {
      try {
        await saveWorkDataToFirestore(dataToSave, docId);
        removeMonthFromPendingList(docId);
        if (pendingKey) localStorage.removeItem(pendingKey);
      } catch (e) {
        addMonthToPendingList(docId);
        if (pendingKey) localStorage.setItem(pendingKey, dataStr);
      }
    } else {
      addMonthToPendingList(docId);
      if (pendingKey) localStorage.setItem(pendingKey, dataStr);
    }
  }

  calculateTotal();
}, 1200);

async function syncPendingWorkData() {
  if (!currentUser || !navigator.onLine) { updateAppBadge(getPendingSyncCount()); return; }

  const pendingMonths = getPendingSyncMonths();
  if (pendingMonths.length === 0) { updateAppBadge(0); return; }

  showNotification('saveNotification', `Synchronizujem ${pendingMonths.length} mesiac(ov) s cloudom...`, 2000);

  const ok = [];
  const failed = [];

  for (const monthId of pendingMonths) {
    const pendingKey = getPendingSyncKeyForMonth(monthId);
    if (!pendingKey) continue;

    const pendingDataStr = localStorage.getItem(pendingKey);
    if (!pendingDataStr) { ok.push(monthId); continue; }

    try {
      const parsed = safeJsonParse(pendingDataStr, null);
      if (!parsed) { ok.push(monthId); localStorage.removeItem(pendingKey); continue; }
      parsed.lastUpdated = new Date().toISOString();
      await saveWorkDataToFirestore(parsed, monthId);
      localStorage.removeItem(pendingKey);
      ok.push(monthId);
    } catch (e) {
      failed.push(monthId);
    }
  }

  if (ok.length) {
    const remain = getPendingSyncMonths().filter(id => !ok.includes(id));
    savePendingSyncMonths(remain);
  }

  const finalCount = getPendingSyncCount();
  if (finalCount === 0 && failed.length === 0) showSaveNotification('Všetky lokálne zmeny boli úspešne synchronizované s cloudom.');
  else showWarningNotification(`Niektoré dáta sa nepodarilo synchronizovať. Zostáva ${finalCount} mesiac(ov) na synchronizáciu.`);
  updateAppBadge(finalCount);
}

// =========================
// Conflict detection (server vs local)
// =========================

async function detectAndHandleConflict(firestoreData, localKey, docId) {
  if (conflictCheckInProgress) return false;
  conflictCheckInProgress = true;

  try {
    const localDataString = localStorage.getItem(localKey);
    if (!localDataString) return false;

    const pendingKey = getPendingSyncKeyForMonth(docId);
    const hasPending = pendingKey && localStorage.getItem(pendingKey);
    if (!hasPending) return false;

    const localData = safeJsonParse(localDataString, null);
    if (!localData) return false;

    const fsTs = firestoreData?.lastUpdated;
    const localTs = localData?.lastUpdated;
    if (!fsTs || !localTs) return false;

    const fsTime = new Date(fsTs?.toDate ? fsTs.toDate() : fsTs).getTime();
    const localTime = new Date(localTs).getTime();
    const diffMinutes = Math.abs(fsTime - localTime) / (1000 * 60);

    const fsDataStr = JSON.stringify(firestoreData?.data || []);
    const localDataStr = JSON.stringify(localData?.data || []);

    if (diffMinutes > 5 && fsDataStr !== localDataStr) {
      const fsHash = fsDataStr.substring(0, 50) + ':' + fsDataStr.length;
      const localHash = localDataStr.substring(0, 50) + ':' + localDataStr.length;
      const conflictKey = `${docId}:${fsTime}:${localTime}:${fsHash}:${localHash}`;

      if (lastConflictKey === conflictKey) {
        showWarningNotification('Konflikt dát - lokálne dáta ponechané.');
        return true; // stop apply server
      }
      lastConflictKey = conflictKey;

      const fsDate = new Date(fsTime).toLocaleString('sk-SK');
      const localDate = new Date(localTime).toLocaleString('sk-SK');

      const msg =
        `⚠️ Detekovaný konflikt dát!\n\n` +
        `Server: ${fsDate}\nLokálne: ${localDate}\n\n` +
        `Použiť dáta zo servera? (Lokálne zmeny budú prepísané)`;

      if (confirm(msg)) {
        if (pendingKey) localStorage.removeItem(pendingKey);
        removeMonthFromPendingList(docId);
        lastConflictKey = null;
        return false; // continue apply server
      } else {
        showWarningNotification('Lokálne dáta ponechané. Synchronizujú sa pri ďalšej zmene.');
        return true; // stop apply server
      }
    }
  } catch (e) {
    // ignore, fallback to normal apply
  } finally {
    conflictCheckInProgress = false;
  }

  return false;
}

// =========================
// Firestore listener
// =========================

function loadWorkDataFromLocalStorage() {
  const docId = getFirestoreDocId(currentYear, currentMonth);
  const localKey = getLocalStorageKeyForWorkData(docId);
  parseAndApplyWorkData(localStorage.getItem(localKey));
}

function setupFirestoreWorkDataListener() {
  if (currentListenerUnsubscribe) currentListenerUnsubscribe();
  snapshotSeq = 0;

  if (!currentUser) { loadWorkDataFromLocalStorage(); return; }
  if (!navigator.onLine) {
    loadWorkDataFromLocalStorage();
    showWarningNotification("Ste offline. Zobrazujem lokálne dáta. Synchronizácia prebehne po pripojení.");
    return;
  }

  const docId = getFirestoreDocId(currentYear, currentMonth);
  const docRef = doc(db, 'users', currentUser.uid, 'workData', docId);

  currentListenerUnsubscribe = onSnapshot(docRef, (snap) => {
    const seq = ++snapshotSeq;
    const localKey = getLocalStorageKeyForWorkData(docId);

    if (!snap.exists()) {
      localStorage.removeItem(localKey);
      const pendingKey = getPendingSyncKeyForMonth(docId);
      if (pendingKey) localStorage.removeItem(pendingKey);
      removeMonthFromPendingList(docId);
      parseAndApplyWorkData(null);
      return;
    }

    const firestoreData = snap.data();
    const firestoreDataString = JSON.stringify(firestoreData);

    const activeEl = document.activeElement;
    const isInputFocused =
      activeEl &&
      (activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA') &&
      activeEl.closest && activeEl.closest('#workDays');

    // never overwrite UI while editing/focused
    if (isUserEditing || isInputFocused) {
      localStorage.setItem(localKey, firestoreDataString);
      if (!snap.metadata.hasPendingWrites) {
        removeMonthFromPendingList(docId);
        const pendingKey = getPendingSyncKeyForMonth(docId);
        if (pendingKey) localStorage.removeItem(pendingKey);
      }
      calculateTotal();
      return;
    }

    // conflict check only when not pending writes
    if (!snap.metadata.hasPendingWrites) {
      detectAndHandleConflict(firestoreData, localKey, docId)
        .then(hasConflict => {
          if (seq !== snapshotSeq) return; // stale snapshot

          if (hasConflict) {
            calculateTotal();
          } else {
            localStorage.setItem(localKey, firestoreDataString);
            removeMonthFromPendingList(docId);
            const pendingKey = getPendingSyncKeyForMonth(docId);
            if (pendingKey) localStorage.removeItem(pendingKey);
            parseAndApplyWorkData(firestoreDataString);
          }
        })
        .catch(() => {
          if (seq !== snapshotSeq) return;
          localStorage.setItem(localKey, firestoreDataString);
          removeMonthFromPendingList(docId);
          const pendingKey = getPendingSyncKeyForMonth(docId);
          if (pendingKey) localStorage.removeItem(pendingKey);
          parseAndApplyWorkData(firestoreDataString);
        });
      return;
    }

    // pending writes => keep calm: store, recalc only
    localStorage.setItem(localKey, firestoreDataString);
    calculateTotal();
  }, (err) => {
    showErrorNotification(`Chyba synchronizácie dát s cloudom: ${err?.message || 'unknown'}. Zobrazujem lokálne uložené dáta.`);
    loadWorkDataFromLocalStorage();
  });

  syncPendingWorkData();
}

// =========================
// Table render + apply data
// =========================

function resetTableInputsOnly() {
  const days = getDaysInMonth(currentMonth, currentYear);
  for (let i = 1; i <= days; i++) {
    const s = $(`start-${i}`); if (s) s.value = '';
    const e = $(`end-${i}`); if (e) e.value = '';
    const b = $(`break-${i}`); if (b) b.value = '';
    const p = $(`project-${i}`); if (p) p.value = '';
    const n = $(`note-${i}`); if (n) n.value = '';
    calculateRow(i);
  }
}

function parseAndApplyWorkData(dataString) {
  if (!dataString) {
    resetTableInputsOnly();
    calculateTotal();
    return;
  }

  try {
    const stored = JSON.parse(dataString);
    if (!stored?.data || !Array.isArray(stored.data)) {
      resetTableInputsOnly();
      calculateTotal();
      return;
    }

    const daysInTable = getDaysInMonth(currentMonth, currentYear);
    stored.data.slice(0, daysInTable).forEach((dayData, idx) => {
      const day = idx + 1;
      const s = $(`start-${day}`); if (s) s.value = dayData?.start || '';
      const e = $(`end-${day}`); if (e) e.value = dayData?.end || '';
      const b = $(`break-${day}`); if (b) b.value = (dayData?.breakTime ?? '') + '';
      const p = $(`project-${day}`); if (p) p.value = dayData?.projectTag || '';
      const n = $(`note-${day}`); if (n) n.value = dayData?.note || '';
      calculateRow(day);
    });

    calculateTotal();
  } catch (e) {
    showErrorNotification('Chyba pri spracovaní uložených dát.');
    resetTableInputsOnly();
    calculateTotal();
  }
}

function createTimeInputCell(inputId, day, type, label) {
  const td = document.createElement('td');
  const wrap = document.createElement('div');
  wrap.className = 'time-input-wrapper';

  const input = document.createElement('input');
  input.type = 'tel';
  input.id = inputId;
  input.maxLength = 5;
  input.placeholder = 'HH:MM';
  input.inputMode = 'numeric';
  input.setAttribute('data-day', String(day));
  input.setAttribute('data-type', type);
  input.setAttribute('aria-label', label);

  const button = document.createElement('button');
  button.className = 'time-btn';
  button.setAttribute('data-target', inputId);
  button.setAttribute('data-day', String(day));
  button.title = 'Zadať aktuálny čas';
  button.textContent = '🕒';

  wrap.appendChild(input);
  wrap.appendChild(button);
  td.appendChild(wrap);

  return td;
}

function createTable() {
  if (!uiRefs.workDaysTbody) return;

  // clear safely
  while (uiRefs.workDaysTbody.firstChild) uiRefs.workDaysTbody.removeChild(uiRefs.workDaysTbody.firstChild);

  const frag = document.createDocumentFragment();

  const today = new Date();
  const isTodayMonth = today.getMonth() === currentMonth && today.getFullYear() === currentYear;
  const todayDay = today.getDate();

  const days = getDaysInMonth(currentMonth, currentYear);
  for (let i = 1; i <= days; i++) {
    const row = document.createElement('tr');
    const dayStr = String(i);

    if (isWeekend(currentYear, currentMonth, i)) row.classList.add('weekend-day');
    if (isTodayMonth && i === todayDay) row.classList.add('current-day');

    // day cell
    const dayCell = document.createElement('td');
    dayCell.textContent = `${i}. ${getDayName(currentYear, currentMonth, i)}`;
    row.appendChild(dayCell);

    // start / end
    row.appendChild(createTimeInputCell(`start-${dayStr}`, i, 'start', `Príchod deň ${dayStr}`));
    row.appendChild(createTimeInputCell(`end-${dayStr}`, i, 'end', `Odchod deň ${dayStr}`));

    // break
    const breakTd = document.createElement('td');
    const breakInput = document.createElement('input');
    breakInput.type = 'text';
    breakInput.inputMode = 'decimal';
    breakInput.id = `break-${dayStr}`;
    breakInput.placeholder = 'hod.';
    breakInput.setAttribute('data-day', dayStr);
    breakInput.setAttribute('data-type', 'break');
    breakInput.maxLength = 10;
    breakTd.appendChild(breakInput);
    row.appendChild(breakTd);

    // total
    const totalTd = document.createElement('td');
    totalTd.id = `total-${dayStr}`;
    totalTd.textContent = `0h 0m 0.${'0'.repeat(Math.max(0, appSettings.decimalPlaces))} h`;
    row.appendChild(totalTd);

    // project
    const projectTd = document.createElement('td');
    const projectInput = document.createElement('input');
    projectInput.type = 'text';
    projectInput.id = `project-${dayStr}`;
    projectInput.className = 'project-input';
    projectInput.placeholder = 'Projekt/úloha';
    projectInput.setAttribute('data-day', dayStr);
    projectInput.setAttribute('data-type', 'project');
    projectInput.maxLength = TEXT_LIMITS.projectTag;
    projectTd.appendChild(projectInput);
    row.appendChild(projectTd);

    // note
    const noteTd = document.createElement('td');
    const note = document.createElement('textarea');
    note.id = `note-${dayStr}`;
    note.rows = 2;
    note.placeholder = 'Poznámka';
    note.setAttribute('data-day', dayStr);
    note.setAttribute('data-type', 'note');
    note.maxLength = TEXT_LIMITS.note;
    noteTd.appendChild(note);
    row.appendChild(noteTd);

    // gross/net
    const grossTd = document.createElement('td');
    const gross = document.createElement('input');
    gross.type = 'number';
    gross.readOnly = true;
    gross.step = '0.01';
    gross.id = `gross-${dayStr}`;
    grossTd.appendChild(gross);
    row.appendChild(grossTd);

    const netTd = document.createElement('td');
    const net = document.createElement('input');
    net.type = 'number';
    net.readOnly = true;
    net.step = '0.01';
    net.id = `net-${dayStr}`;
    netTd.appendChild(net);
    row.appendChild(netTd);

    // reset
    const resetTd = document.createElement('td');
    resetTd.className = 'actions-cell';
    const resetBtn = document.createElement('button');
    resetBtn.className = 'btn reset-btn';
    resetBtn.textContent = 'X';
    resetBtn.setAttribute('data-action', 'reset');
    resetBtn.setAttribute('data-day', dayStr);
    resetTd.appendChild(resetBtn);
    row.appendChild(resetTd);

    frag.appendChild(row);
  }

  uiRefs.workDaysTbody.appendChild(frag);
}

// =========================
// Calculations
// =========================

function handleNumericInput(inputElement) {
  let v = String(inputElement.value ?? '');
  v = v.replace(',', '.');
  v = v.replace(/[^\d.]/g, '').replace(/(\..*)\./g, '$1');
  inputElement.value = v;
}

function validateAndFormatTimeBlur(input, day) {
  formatTimeInputOnly(input);
  const isValid = input.value.length === 0 || isValidTimeFormat(input.value);
  input.classList.toggle('invalid-time', !isValid);

  if (!isValid) {
    showWarningNotification(`Neplatný formát času pre deň ${day}. Použite HH:MM.`);
  }
  calculateRow(day);
  debouncedSaveWorkDataAndSync();
}

function validateBreakInputOnBlur(day) {
  const breakInput = $(`break-${day}`);
  if (!breakInput) return;

  let v = String(breakInput.value ?? '').replace(',', '.');
  const n = parseFloat(v);

  breakInput.classList.remove('invalid-value');
  if (v && (!Number.isFinite(n) || n < 0)) {
    breakInput.classList.add('invalid-value');
    showWarningNotification(`Neplatná hodnota prestávky pre deň ${day}.`);
  }
  calculateRow(day);
  debouncedSaveWorkDataAndSync();
}

function setCurrentTime(inputId) {
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const input = $(inputId);
  if (!input) return;
  input.value = `${hh}:${mm}`;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('blur', { bubbles: true }));
}

function handleTimeInput(input, nextId, day) {
  setUserEditing();
  formatTimeInputOnly(input);

  if (input.value.length === 5 && isValidTimeFormat(input.value)) {
    calculateRow(day);
    debouncedSaveWorkDataAndSync();

    const nextEl = $(nextId);
    if (nextEl && document.activeElement === input && !nextId.startsWith('break-')) {
      nextEl.focus();
      if (typeof nextEl.select === 'function') nextEl.select();
    }
  } else {
    calculateRow(day);
  }
}

function calculateRow(day) {
  const start = $(`start-${day}`);
  const end = $(`end-${day}`);
  const brk = $(`break-${day}`);
  const totalCell = $(`total-${day}`);
  const gross = $(`gross-${day}`);
  const net = $(`net-${day}`);

  if (!totalCell || !gross || !net) return;

  if (start) start.classList.remove('invalid-time');
  if (end) end.classList.remove('invalid-time');
  if (brk) brk.classList.remove('invalid-value');

  const startTime = start?.value || '';
  const endTime = end?.value || '';
  const breakRaw = String(brk?.value ?? '').replace(',', '.');
  const breakHours = parseFloat(breakRaw);

  let decimalHours = 0;

  if (isValidTimeFormat(startTime) && isValidTimeFormat(endTime)) {
    const [sH, sM] = startTime.split(':').map(Number);
    const [eH, eM] = endTime.split(':').map(Number);

    let startDate = new Date(2000, 0, 1, sH, sM, 0);
    let endDate = new Date(2000, 0, 1, eH, eM, 0);
    if (endDate < startDate) endDate.setDate(endDate.getDate() + 1);

    let totalMinutes = (endDate.getTime() - startDate.getTime()) / 60000;
    if (breakRaw.length > 0) {
      if (!Number.isFinite(breakHours) || breakHours < 0) {
        brk?.classList.add('invalid-value');
      } else {
        totalMinutes -= (breakHours * 60);
      }
    }
    if (totalMinutes < 0) totalMinutes = 0;
    decimalHours = totalMinutes / 60;
  } else {
    if (startTime && !isValidTimeFormat(startTime)) start?.classList.add('invalid-time');
    if (endTime && !isValidTimeFormat(endTime)) end?.classList.add('invalid-time');
    if (breakRaw && (!Number.isFinite(breakHours) || breakHours < 0)) brk?.classList.add('invalid-value');
  }

  const hoursPart = Math.floor(decimalHours);
  const minutesPart = Math.round((decimalHours - hoursPart) * 60);
  totalCell.textContent = `${hoursPart}h ${minutesPart}m ${decimalHours.toFixed(appSettings.decimalPlaces)} h`;

  const wage = Number.isFinite(appSettings.hourlyWage) ? appSettings.hourlyWage : 0;
  const tax = Number.isFinite(appSettings.taxRate) ? appSettings.taxRate : 0;

  const grossSalary = decimalHours * wage;
  const netSalary = grossSalary * (1 - tax);

  gross.value = Math.max(0, grossSalary).toFixed(appSettings.decimalPlaces);
  net.value = Math.max(0, netSalary).toFixed(appSettings.decimalPlaces);
}

function calculateTotal() {
  if (!uiRefs.totalSalaryDiv) return;

  const days = getDaysInMonth(currentMonth, currentYear);
  let totalHours = 0;
  let daysWithEntries = 0;

  for (let i = 1; i <= days; i++) {
    const s = $(`start-${i}`)?.value || '';
    const e = $(`end-${i}`)?.value || '';
    const b = String($(`break-${i}`)?.value || '').replace(',', '.');
    const p = ($(`project-${i}`)?.value || '').trim();
    const n = ($(`note-${i}`)?.value || '').trim();

    let dayHours = 0;
    if (isValidTimeFormat(s) && isValidTimeFormat(e)) {
      const [sH, sM] = s.split(':').map(Number);
      const [eH, eM] = e.split(':').map(Number);
      let sd = new Date(2000, 0, 1, sH, sM, 0);
      let ed = new Date(2000, 0, 1, eH, eM, 0);
      if (ed < sd) ed.setDate(ed.getDate() + 1);

      let mins = (ed - sd) / 60000;
      const brk = parseFloat(b || '0');
      if (Number.isFinite(brk) && brk > 0) mins -= brk * 60;
      if (mins < 0) mins = 0;
      dayHours = mins / 60;
    }

    totalHours += dayHours;
    if ((isValidTimeFormat(s) && isValidTimeFormat(e) && dayHours > 0) || p || n) daysWithEntries++;
  }

  const wage = Number.isFinite(appSettings.hourlyWage) ? appSettings.hourlyWage : 0;
  const tax = Number.isFinite(appSettings.taxRate) ? appSettings.taxRate : 0;

  const totalGross = totalHours * wage;
  const totalNet = totalGross * (1 - tax);

  const totalH = Math.floor(totalHours);
  const totalM = Math.round((totalHours - totalH) * 60);

  uiRefs.totalSalaryDiv.textContent = '';
  const line = (parts) => {
    const frag = document.createDocumentFragment();
    for (const part of parts) {
      if (part.bold) {
        const strong = document.createElement('strong');
        strong.textContent = part.text;
        frag.appendChild(strong);
      } else {
        frag.appendChild(document.createTextNode(part.text));
      }
    }
    return frag;
  };

  uiRefs.totalSalaryDiv.appendChild(line([
    { text: 'Započítaných dní s aktivitou: ' },
    { text: String(daysWithEntries), bold: true }
  ]));
  uiRefs.totalSalaryDiv.appendChild(document.createElement('br'));

  uiRefs.totalSalaryDiv.appendChild(line([
    { text: 'Celkový odpracovaný čas: ' },
    { text: `${totalH}h ${totalM}m`, bold: true },
    { text: ` (${totalHours.toFixed(appSettings.decimalPlaces)} h)` }
  ]));
  uiRefs.totalSalaryDiv.appendChild(document.createElement('br'));

  uiRefs.totalSalaryDiv.appendChild(line([
    { text: 'Celková hrubá mzda: ' },
    { text: `${totalGross.toFixed(appSettings.decimalPlaces)} €`, bold: true },
    { text: ' | Celková čistá mzda: ' },
    { text: `${totalNet.toFixed(appSettings.decimalPlaces)} €`, bold: true },
  ]));
}

// =========================
// Actions
// =========================

function resetRow(dayStr) {
  const day = parseInt(dayStr, 10);
  if (!Number.isFinite(day)) return;

  if (!confirm(`Naozaj chcete vymazať záznam pre ${day}. deň?`)) return;

  const s = $(`start-${day}`); if (s) s.value = '';
  const e = $(`end-${day}`); if (e) e.value = '';
  const b = $(`break-${day}`); if (b) b.value = '';
  const p = $(`project-${day}`); if (p) p.value = '';
  const n = $(`note-${day}`); if (n) n.value = '';

  calculateRow(day);
  debouncedSaveWorkDataAndSync();
  showSaveNotification(`Záznam pre ${day}. deň bol vymazaný.`);
}

function updatePageTitleAndGreeting() {
  if (!uiRefs.mainTitle || !uiRefs.subTitle) return;
  const namePart = appSettings.employeeName ? ` ${appSettings.employeeName.split(' ')[0]}` : '';
  uiRefs.mainTitle.textContent = `Vitaj${namePart} 👋`;
  uiRefs.subTitle.textContent = `${MONTH_NAMES[currentMonth]} ${currentYear}`;

  const titleNamePart = appSettings.employeeName ? `${appSettings.employeeName} - ` : '';
  document.title = `${titleNamePart}${MONTH_NAMES[currentMonth]} ${currentYear} | Bruno's Calc Pro+`;
}

function changeMonth() {
  if (!uiRefs.monthSelect) return;
  currentMonth = parseInt(uiRefs.monthSelect.value, 10);
  createTable();
  setupFirestoreWorkDataListener();
  updatePageTitleAndGreeting();
}
function changeYear() {
  if (!uiRefs.yearSelect) return;
  currentYear = parseInt(uiRefs.yearSelect.value, 10);
  createTable();
  setupFirestoreWorkDataListener();
  updatePageTitleAndGreeting();
}

function handleWageOrTaxBlur(input) {
  const id = input.id;
  let valueString = String(input.value ?? '').replace(',', '.');
  const value = parseFloat(valueString);

  input.classList.remove('invalid-value');

  if (id === 'hourlyWageInput') {
    if (Number.isFinite(value) && value >= 0) {
      appSettings.hourlyWage = value;
      input.value = value.toFixed(appSettings.decimalPlaces > 0 ? appSettings.decimalPlaces : 1);
      saveAppSettingToLocalStorage('hourlyWage', appSettings.hourlyWage);
    } else {
      input.classList.add('invalid-value');
      showErrorNotification('Neplatná hodinová mzda.');
      return;
    }
  }

  if (id === 'taxRateInput') {
    if (Number.isFinite(value) && value >= 0 && value <= 100) {
      appSettings.taxRate = value / 100;
      input.value = value.toFixed(1);
      saveAppSettingToLocalStorage('taxRate', appSettings.taxRate);
    } else {
      input.classList.add('invalid-value');
      showErrorNotification('Neplatné daňové percento.');
      return;
    }
  }

  calculateTotal();
  debouncedSaveAppSettingsToFirestore();
}

function changeDecimalPlaces() {
  if (!uiRefs.decimalPlacesSelect) return;
  appSettings.decimalPlaces = parseInt(uiRefs.decimalPlacesSelect.value, 10) || 2;
  saveAppSettingToLocalStorage('decimalPlaces', appSettings.decimalPlaces);
  updateSettingsUIInputs();
  // recalc all rows
  const days = getDaysInMonth(currentMonth, currentYear);
  for (let i = 1; i <= days; i++) calculateRow(i);
  calculateTotal();
  debouncedSaveAppSettingsToFirestore();
}

// =========================
// Event listeners (delegation)
// =========================

function setupEventListeners() {
  // Auth
  if (uiRefs.loginBtn) uiRefs.loginBtn.addEventListener('click', loginUser);
  if (uiRefs.registerBtn) uiRefs.registerBtn.addEventListener('click', registerUser);
  if (uiRefs.resetPasswordLink) uiRefs.resetPasswordLink.addEventListener('click', (e) => { e.preventDefault(); resetUserPassword(); });
  if (uiRefs.logoutBtn) uiRefs.logoutBtn.addEventListener('click', logoutUser);

  // Month/year
  if (uiRefs.monthSelect) uiRefs.monthSelect.addEventListener('change', changeMonth);
  if (uiRefs.yearSelect) uiRefs.yearSelect.addEventListener('change', changeYear);

  // Settings inputs
  if (uiRefs.employeeNameInput) {
    uiRefs.employeeNameInput.addEventListener('input', () => {
      saveAppSettingToLocalStorage('employeeName', sanitizeText(uiRefs.employeeNameInput.value, TEXT_LIMITS.employeeName));
      updatePageTitleAndGreeting();
      debouncedSaveAppSettingsToFirestore();
    });
  }

  if (uiRefs.hourlyWageInput) {
    uiRefs.hourlyWageInput.addEventListener('input', () => handleNumericInput(uiRefs.hourlyWageInput));
    uiRefs.hourlyWageInput.addEventListener('blur', () => handleWageOrTaxBlur(uiRefs.hourlyWageInput));
  }

  if (uiRefs.taxRateInput) {
    uiRefs.taxRateInput.addEventListener('input', () => handleNumericInput(uiRefs.taxRateInput));
    uiRefs.taxRateInput.addEventListener('blur', () => handleWageOrTaxBlur(uiRefs.taxRateInput));
  }

  if (uiRefs.decimalPlacesSelect) {
    uiRefs.decimalPlacesSelect.addEventListener('change', changeDecimalPlaces);
  }

  // Delegation for table
  if (uiRefs.workDaysTbody) {
    uiRefs.workDaysTbody.addEventListener('click', (e) => {
      const t = e.target;

      if (t?.classList?.contains('time-btn')) {
        const inputId = t.dataset.target;
        setCurrentTime(inputId);
        return;
      }

      if (t?.dataset?.action === 'reset') {
        resetRow(t.dataset.day);
      }
    });

    uiRefs.workDaysTbody.addEventListener('input', (e) => {
      const t = e.target;
      const day = parseInt(t?.dataset?.day, 10);
      const type = t?.dataset?.type;
      if (!type || !Number.isFinite(day)) return;

      setUserEditing();

      if (type === 'start') handleTimeInput(t, `end-${day}`, day);
      else if (type === 'end') handleTimeInput(t, `break-${day}`, day);
      else if (type === 'break') { handleNumericInput(t); calculateRow(day); debouncedSaveWorkDataAndSync(); }
      else if (type === 'project') debouncedSaveWorkDataAndSync();
      else if (type === 'note') debouncedSaveWorkDataAndSync();
    }, true);

    uiRefs.workDaysTbody.addEventListener('blur', (e) => {
      const t = e.target;
      const day = parseInt(t?.dataset?.day, 10);
      const type = t?.dataset?.type;
      if (!type || !Number.isFinite(day)) return;

      if (type === 'start' || type === 'end') validateAndFormatTimeBlur(t, day);
      else if (type === 'break') validateBreakInputOnBlur(day);
      else debouncedSaveWorkDataAndSync();
    }, true);
  }

  // Online/offline
  window.addEventListener('online', async () => {
    showNotification('saveNotification', 'Ste opäť online. Synchronizácia dát môže prebiehať.', 3000);
    if (!currentUser) return;
    if (!didLoadSettingsFromFirestore) await loadUserAppSettingsFromFirestore();
    await syncPendingWorkData();
    setupFirestoreWorkDataListener();
    if (appSettingsDirty) debouncedSaveAppSettingsToFirestore();
  });

  window.addEventListener('offline', () => {
    showNotification('warningNotification', 'Ste offline. Zmeny sa ukladajú lokálne a zosynchronizujú sa po pripojení.', 4000);
  });
}

// =========================
// Init UI
// =========================

function initializeUI() {
  loadAppSettingsFromLocalStorage();
  ThemeManager.init();
  setupEventListeners();

  // populate month/year selects
  if (uiRefs.monthSelect && uiRefs.monthSelect.options.length === 0) {
    MONTH_NAMES.forEach((name, idx) => {
      const opt = document.createElement('option');
      opt.value = String(idx);
      opt.textContent = name;
      uiRefs.monthSelect.appendChild(opt);
    });
  }

  if (uiRefs.yearSelect && uiRefs.yearSelect.options.length === 0) {
    const startYear = 2020;
    const endYear = new Date().getFullYear() + 5;
    for (let y = startYear; y <= endYear; y++) {
      const opt = document.createElement('option');
      opt.value = String(y);
      opt.textContent = String(y);
      uiRefs.yearSelect.appendChild(opt);
    }
  }

  if (uiRefs.monthSelect) uiRefs.monthSelect.value = String(currentMonth);
  if (uiRefs.yearSelect) uiRefs.yearSelect.value = String(currentYear);

  updateSettingsUIInputs();
  createTable();
  updatePageTitleAndGreeting();
  updateLocalStorageSizeIndicator();
  updateAppBadge(getPendingSyncCount());

  // basic visibility
  if (uiRefs.mainContainer) uiRefs.mainContainer.classList.add('visible-block');
}

// =========================
// Auth state listener
// =========================

onAuthStateChanged(auth, async (user) => {
  currentUser = user || null;

  didLoadSettingsFromFirestore = false;
  appSettingsDirty = false;

  updateUIForAuthStateChange();

  if (user) {
    const loaded = await loadUserAppSettingsFromFirestore();
    if (!loaded) loadAppSettingsFromLocalStorage();
    updateSettingsUIInputs();
    ThemeManager.applyTheme(appSettings.theme);

    if (navigator.onLine) {
      await saveAppSettingsToFirestore();
      await syncPendingWorkData();
    }
  } else {
    // guest mode: keep local settings, clear pending list
    loadAppSettingsFromLocalStorage();
    updateSettingsUIInputs();
    ThemeManager.applyTheme(appSettings.theme);
    localStorage.removeItem(PENDING_SYNC_MONTHS_LS_KEY);
    updateAppBadge(0);
  }

  createTable();
  setupFirestoreWorkDataListener();
  updatePageTitleAndGreeting();

  if (uiRefs.appLoader) uiRefs.appLoader.classList.add('hidden');
  if (uiRefs.mainContainer) uiRefs.mainContainer.classList.remove('container-hidden');
});

// Start
initializeUI();
