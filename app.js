// Firebase Modular SDK Imports
import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-app.js';
import {
  initializeFirestore,
  doc,
  getDoc,
  setDoc,
  onSnapshot,
  persistentLocalCache,
  persistentMultipleTabManager,
  serverTimestamp
} from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js';
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  sendPasswordResetEmail,
  onAuthStateChanged
} from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js';
import { initializeAppCheck, ReCaptchaV3Provider } from 'https://www.gstatic.com/firebasejs/12.7.0/firebase-app-check.js';

// Firebase Config & Init
const firebaseConfig = {
  apiKey: "AIzaSyDWFiWPldB7aWPIuFhAmriAm_DR38rndIo",
  authDomain: "bruno-3cee2.firebaseapp.com",
  projectId: "bruno-3cee2",
  storageBucket: "bruno-3cee2.appspot.com",
  messagingSenderId: "155545319308",
  appId: "1:155545319308:web:5da498ff1cd3e1833888a9"
};

const app = initializeApp(firebaseConfig);

// App Check s reCAPTCHA v3
try {
  initializeAppCheck(app, {
    provider: new ReCaptchaV3Provider('6LcagP8qAAAAAN3MIW5-ALzayoS57THfEvO1yUTv'),
    isTokenAutoRefreshEnabled: true
  });
} catch (error) {
  console.warn("Chyba pri aktivácii Firebase App Check:", error);
}

// Firestore s offline persistence (bez deprecation warning)
const db = initializeFirestore(app, {
  localCache: persistentLocalCache({
    tabManager: persistentMultipleTabManager()
  })
});

const auth = getAuth(app);

// Globálne premenné
let currentMonth, currentYear, decimalPlaces, employeeName, hourlyWage, taxRate;
let monthData = {};
let firestoreListenerUnsubscribe = null;

// NOVÉ: Tracking aktívnych zmien a timestamp
let localChangeTimestamp = 0;
let isUserEditing = false;
let editingTimeout = null;
let pendingChanges = new Set(); // Track ktoré polia sa práve menia
let eventListenersAttached = false; // Guard pre event delegation

const workDays = document.getElementById('workDays');
const totalSalaryDiv = document.getElementById('totalSalary');
const dataSizeText = document.getElementById('dataSizeText');
const dataSizeFill = document.getElementById('dataSizeFill');
const hourlyWageInput = document.getElementById('hourlyWageInput');
const taxRateInput = document.getElementById('taxRateInput');
const monthSelect = document.getElementById('monthSelect');
const yearSelect = document.getElementById('yearSelect');
const decimalPlacesSelect = document.getElementById('decimalPlacesSelect');
const employeeNameInput = document.getElementById('employeeNameInput');
const MAX_DATA_SIZE = 4 * 1024 * 1024;
const MAX_DATA_SIZE_KB = MAX_DATA_SIZE / 1024;

// ========================================
// INPUT VALIDATION UTILITIES
// ========================================

const VALIDATION_RULES = {
  TIME_REGEX: /^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$/,
  EMAIL_REGEX: /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  MAX_NOTE_LENGTH: 500,
  MIN_PASSWORD_LENGTH: 8,
  MAX_HOURLY_WAGE: 100,
  MAX_TAX_RATE: 100,
  MAX_BREAK_HOURS: 12
};

// Validácia času (HH:MM)
function validateTime(timeString) {
  if (!timeString || timeString.trim() === '') {
    return { valid: true, value: '', error: null }; // Prázdne je OK
  }

  const trimmed = timeString.trim();

  if (!VALIDATION_RULES.TIME_REGEX.test(trimmed)) {
    return {
      valid: false,
      value: trimmed,
      error: 'Neplatný formát času. Použite HH:MM (napr. 08:30)'
    };
  }

  const [hours, minutes] = trimmed.split(':').map(Number);

  if (hours < 0 || hours > 23) {
    return { valid: false, value: trimmed, error: 'Hodiny musia byť 0-23' };
  }

  if (minutes < 0 || minutes > 59) {
    return { valid: false, value: trimmed, error: 'Minúty musia byť 0-59' };
  }

  return { valid: true, value: trimmed, error: null };
}

// Validácia čísla s rozsahom
function validateNumber(value, min = 0, max = Infinity, fieldName = 'Hodnota') {
  if (value === '' || value === null || value === undefined) {
    return { valid: true, value: '', error: null }; // Prázdne je OK
  }

  const num = parseFloat(value);

  if (isNaN(num)) {
    return { valid: false, value, error: `${fieldName} musí byť číslo` };
  }

  if (num < min) {
    return { valid: false, value, error: `${fieldName} nesmie byť menšia ako ${min}` };
  }

  if (num > max) {
    return { valid: false, value, error: `${fieldName} nesmie byť väčšia ako ${max}` };
  }

  return { valid: true, value: num, error: null };
}

// Validácia poznámky
function validateNote(noteText) {
  if (!noteText || noteText.trim() === '') {
    return { valid: true, value: '', error: null, length: 0 };
  }

  const trimmed = noteText.trim();
  const length = trimmed.length;

  if (length > VALIDATION_RULES.MAX_NOTE_LENGTH) {
    return {
      valid: false,
      value: trimmed.substring(0, VALIDATION_RULES.MAX_NOTE_LENGTH),
      error: `Poznámka je príliš dlhá (max ${VALIDATION_RULES.MAX_NOTE_LENGTH} znakov)`,
      length: VALIDATION_RULES.MAX_NOTE_LENGTH
    };
  }

  return { valid: true, value: trimmed, error: null, length };
}

// Validácia emailu
function validateEmail(email) {
  if (!email || email.trim() === '') {
    return { valid: false, value: '', error: 'Email je povinný' };
  }

  const trimmed = email.trim().toLowerCase();

  if (trimmed.length > 254) {
    return { valid: false, value: trimmed, error: 'Email je príliš dlhý' };
  }

  if (!VALIDATION_RULES.EMAIL_REGEX.test(trimmed)) {
    return { valid: false, value: trimmed, error: 'Neplatný formát emailu' };
  }

  return { valid: true, value: trimmed, error: null };
}

// Validácia hesla
function validatePassword(password) {
  if (!password || password.length === 0) {
    return { valid: false, value: '', error: 'Heslo je povinné' };
  }

  if (password.length < VALIDATION_RULES.MIN_PASSWORD_LENGTH) {
    return {
      valid: false,
      value: password,
      error: `Heslo musí mať aspoň ${VALIDATION_RULES.MIN_PASSWORD_LENGTH} znakov`
    };
  }

  // Kontrola zložitosti (aspoň 1 číslo a 1 písmeno)
  const hasNumber = /\d/.test(password);
  const hasLetter = /[a-zA-Z]/.test(password);

  if (!hasNumber || !hasLetter) {
    return {
      valid: false,
      value: password,
      error: 'Heslo musí obsahovať aspoň 1 číslo a 1 písmeno'
    };
  }

  return { valid: true, value: password, error: null };
}

// Zobrazenie validačnej chyby
function showValidationError(element, errorMessage) {
  if (!element) return;

  element.classList.add('validation-error');
  element.classList.remove('validation-success');
  element.title = errorMessage;

  // Odstráň error class po 3 sekundách
  setTimeout(() => {
    element.classList.remove('validation-error');
    if (!element.title || element.title === errorMessage) {
      element.title = '';
    }
  }, 3000);
}

// Odstránenie validačnej chyby
function clearValidationError(element) {
  if (!element) return;
  element.classList.remove('validation-error');
  element.classList.add('validation-success');
  element.title = '';

  // Odstráň success class po 1 sekunde
  setTimeout(() => {
    element.classList.remove('validation-success');
  }, 1000);
}

// ========================================
// SAFE ERROR HANDLING (Information Disclosure Prevention)
// ========================================

// Firebase Auth Error Code Mapping
const AUTH_ERROR_MESSAGES = {
  // Login errors
  'auth/invalid-credential': 'Nesprávny email alebo heslo.',
  'auth/user-not-found': 'Nesprávny email alebo heslo.',
  'auth/wrong-password': 'Nesprávny email alebo heslo.',
  'auth/invalid-email': 'Neplatný formát emailu.',
  'auth/user-disabled': 'Tento účet bol zablokovaný. Kontaktujte podporu.',

  // Registration errors
  'auth/email-already-in-use': 'Email už existuje. Skúste sa prihlásiť.',
  'auth/weak-password': 'Heslo je príliš slabé. Použite aspoň 8 znakov.',
  'auth/operation-not-allowed': 'Registrácia je momentálne nedostupná.',

  // Rate limiting
  'auth/too-many-requests': 'Príliš veľa pokusov. Skúste znova o 5 minút.',

  // Network errors
  'auth/network-request-failed': 'Problém s pripojením. Skontrolujte internet.',
  'auth/timeout': 'Požiadavka vypršala. Skúste znova.',

  // Password reset
  'auth/expired-action-code': 'Odkaz na obnovenie hesla vypršal.',
  'auth/invalid-action-code': 'Neplatný odkaz na obnovenie hesla.',
  'auth/user-token-expired': 'Session vypršala. Prihláste sa znova.',

  // Generic fallback
  'default': 'Nastala chyba. Skúste to neskôr.'
};

// Bezpečné zobrazenie error správy
function handleAuthError(error, context = 'auth') {
  // Log detailnú chybu do konzoly (iba v development)
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    console.error(`[${context}] Detailná chyba:`, {
      code: error.code,
      message: error.message,
      stack: error.stack
    });
  } else {
    // V production loguj len error code
    console.error(`[${context}] Chyba:`, error.code || 'unknown');
  }

  // Vráť user-friendly správu (bez information disclosure)
  const userMessage = AUTH_ERROR_MESSAGES[error.code] || AUTH_ERROR_MESSAGES['default'];
  return userMessage;
}

// Bezpečné zobrazenie alert správy
function showSafeAlert(message, type = 'info') {
  // V budúcnosti môžeme nahradiť alert() custom notification UI
  alert(message);
}

// Generic error handler pre Firestore
function handleFirestoreError(error, operation = 'operácia') {
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    console.error(`[Firestore ${operation}] Chyba:`, error);
  } else {
    console.error(`[Firestore ${operation}] Chyba:`, error.code || 'unknown');
  }

  // Generické správy pre Firestore errors
  const firestoreErrors = {
    'permission-denied': 'Nemáte oprávnenie na túto operáciu.',
    'unavailable': 'Služba je momentálne nedostupná. Skúste neskôr.',
    'deadline-exceeded': 'Operácia trvala príliš dlho. Skúste znova.',
    'not-found': 'Požadované dáta neboli nájdené.',
    'already-exists': 'Dáta už existujú.',
    'resource-exhausted': 'Dosiahnutý limit požiadaviek. Skúste neskôr.',
    'default': 'Nastala chyba pri ukladaní dát.'
  };

  return firestoreErrors[error.code] || firestoreErrors['default'];
}

// Auth funkcie
function register() {
  const emailInput = document.getElementById('registerEmail');
  const passwordInput = document.getElementById('registerPassword');

  const emailValidation = validateEmail(emailInput.value);
  const passwordValidation = validatePassword(passwordInput.value);

  // Validácia emailu
  if (!emailValidation.valid) {
    showValidationError(emailInput, emailValidation.error);
    alert(emailValidation.error);
    return;
  }

  // Validácia hesla
  if (!passwordValidation.valid) {
    showValidationError(passwordInput, passwordValidation.error);
    alert(passwordValidation.error);
    return;
  }

  clearValidationError(emailInput);
  clearValidationError(passwordInput);

  createUserWithEmailAndPassword(auth, emailValidation.value, passwordValidation.value)
    .then(() => {
      showSafeAlert("Registrácia úspešná!");
    })
    .catch((error) => {
      const safeMessage = handleAuthError(error, 'register');
      showSafeAlert(safeMessage);
    });
}

function login() {
  const emailInput = document.getElementById('loginEmail');
  const passwordInput = document.getElementById('loginPassword');

  const emailValidation = validateEmail(emailInput.value);

  // Validácia emailu
  if (!emailValidation.valid) {
    showValidationError(emailInput, emailValidation.error);
    alert(emailValidation.error);
    return;
  }

  // Pre login nekontrolujeme zložitosť hesla, len či je vyplnené
  if (!passwordInput.value || passwordInput.value.trim() === '') {
    showValidationError(passwordInput, 'Heslo je povinné');
    alert('Heslo je povinné');
    return;
  }

  clearValidationError(emailInput);
  clearValidationError(passwordInput);

  signInWithEmailAndPassword(auth, emailValidation.value, passwordInput.value)
    .then(() => {
      showSafeAlert("Prihlásenie úspešné!");
    })
    .catch((error) => {
      const safeMessage = handleAuthError(error, 'login');
      showSafeAlert(safeMessage);
    });
}

function logout() {
  // Vymaž offline auth data
  localStorage.removeItem('lastAuthUser');
  localStorage.setItem('offlineMode', 'false');

  signOut(auth)
    .then(() => {
      showSafeAlert("Odhlásenie úspešné!");
    })
    .catch((error) => {
      const safeMessage = handleAuthError(error, 'logout');
      showSafeAlert(safeMessage);
    });
}

function forgotPassword() {
  const emailInput = document.getElementById('loginEmail');
  const email = emailInput.value;

  if (!email || email.trim() === '') {
    showSafeAlert("Prosím, zadajte svoju e-mailovú adresu do poľa pre prihlásenie.");
    emailInput.focus();
    return;
  }

  // Validácia emailu pred odoslaním
  const emailValidation = validateEmail(email);
  if (!emailValidation.valid) {
    showSafeAlert(emailValidation.error);
    emailInput.focus();
    return;
  }

  sendPasswordResetEmail(auth, emailValidation.value)
    .then(() => {
      showSafeAlert("Odkaz na obnovenie hesla bol odoslaný na vašu e-mailovú adresu.");
    })
    .catch((error) => {
      const safeMessage = handleAuthError(error, 'forgotPassword');
      showSafeAlert(safeMessage);
    });
}

// ========================================
// INIT APP - Auth State Change listener
// ========================================
// Poznámka: Firestore persistence je nastavená pri inicializácii (persistentLocalCache)
function initApp() {
  // Auth State Change with Offline Support
  onAuthStateChanged(auth, user => {
  const authContainer = document.getElementById('auth-container');
  const calculatorContainer = document.getElementById('calculator-container');

  if (firestoreListenerUnsubscribe) {
    firestoreListenerUnsubscribe();
    firestoreListenerUnsubscribe = null;
  }

  // OFFLINE SUPPORT: Ak nie je user (offline), check localStorage
  if (!user) {
    const lastAuthUser = localStorage.getItem('lastAuthUser');
    const isOffline = !navigator.onLine;

    // Ak máme lastAuthUser a sme offline, alebo explicitne offlineMode
    if (lastAuthUser && isOffline) {
      // Offline režim - zobraz data z localStorage
      document.getElementById('auth-message').textContent = "Offline režim: " + lastAuthUser;
      authContainer.classList.add('hidden');
      calculatorContainer.classList.remove('hidden');

      // Načítaj všetko z localStorage (bez Firebase)
      loadOfflineData();
      return; // Skonči tu, nevolaj Firebase operácie
    }
  }

  if (user) {
    // Online režim - normálne prihlásenie
    localStorage.setItem('lastAuthUser', user.email);
    localStorage.setItem('offlineMode', 'false');
    document.getElementById('auth-message').textContent = "Prihlásený: " + user.email;
    authContainer.classList.add('hidden');
    calculatorContainer.classList.remove('hidden');

    const storedMonth = localStorage.getItem('currentMonth');
    const storedYear = localStorage.getItem('currentYear');
    const darkMode = JSON.parse(localStorage.getItem('darkMode')) || false;
    const currentDate = new Date();
    
    currentMonth = storedMonth !== null ? parseInt(storedMonth) : currentDate.getMonth();
    currentYear = storedYear !== null ? parseInt(storedYear) : currentDate.getFullYear();
    
    monthSelect.value = currentMonth;
    if (yearSelect.querySelector(`option[value="${currentYear}"]`)) {
      yearSelect.value = currentYear;
    } else {
      currentYear = currentDate.getFullYear();
      populateYearSelect();
      yearSelect.value = currentYear;
    }

    applyDarkMode(darkMode);
    
    hourlyWage = parseFloat(JSON.parse(localStorage.getItem('hourlyWage'))) || 10;
    taxRate = parseFloat(JSON.parse(localStorage.getItem('taxRate'))) / 100 || 0.02;
    decimalPlaces = parseInt(JSON.parse(localStorage.getItem('decimalPlaces'))) || 1;
    employeeName = JSON.parse(localStorage.getItem('employeeName')) || '';
    
    hourlyWageInput.value = hourlyWage;
    taxRateInput.value = taxRate * 100;
    decimalPlacesSelect.value = decimalPlaces;
    employeeNameInput.value = employeeName;

    loadFromLocalStorage();
    setupFirestoreListener();

    const uid = user.uid;
    const userDocRef = doc(db, "users", uid);
    getDoc(userDocRef).then(userDocSnap => {
      if (!userDocSnap.exists()) {
        setDoc(userDocRef, { email: user.email, createdAt: new Date().toISOString() }, { merge: true })
          .catch(err => console.error("Chyba pri vytváraní dokumentu používateľa:", err));
      }
    }).catch(err => { console.error("Chyba pri kontrole dokumentu:", err); });

  } else {
    // User=null môže znamenať: 1) odhlásený 2) offline
    // Ak nie je lastAuthUser, je to skutočný logout
    const lastAuthUser = localStorage.getItem('lastAuthUser');

    if (!lastAuthUser) {
      // Skutočný logout - vymaž všetko
      document.getElementById('auth-message').textContent = "Žiadny používateľ nie je prihlásený.";
      authContainer.classList.remove('hidden');
      calculatorContainer.classList.add('hidden');
      monthData = {};
      workDays.replaceChildren();
      totalSalaryDiv.textContent = '';
      updateWelcomeMessage();
      localStorage.setItem('offlineMode', 'false');
    }
    // Inak je offline - loadOfflineData() sa už zavolalo vyššie
  }
  });
}

// Offline Data Loader (bez Firebase)
function loadOfflineData() {
  try {
    // Nastav UI z localStorage
    const storedMonth = localStorage.getItem('currentMonth');
    const storedYear = localStorage.getItem('currentYear');
    const darkMode = JSON.parse(localStorage.getItem('darkMode')) || false;
    const currentDate = new Date();

    currentMonth = storedMonth !== null ? parseInt(storedMonth) : currentDate.getMonth();
    currentYear = storedYear !== null ? parseInt(storedYear) : currentDate.getFullYear();

    monthSelect.value = currentMonth;
    populateYearSelect();
    yearSelect.value = currentYear;

    applyDarkMode(darkMode);

    hourlyWage = parseFloat(JSON.parse(localStorage.getItem('hourlyWage'))) || 10;
    taxRate = parseFloat(JSON.parse(localStorage.getItem('taxRate'))) / 100 || 0.02;
    decimalPlaces = parseInt(JSON.parse(localStorage.getItem('decimalPlaces'))) || 1;
    employeeName = JSON.parse(localStorage.getItem('employeeName')) || '';

    hourlyWageInput.value = hourlyWage;
    taxRateInput.value = taxRate * 100;
    decimalPlacesSelect.value = decimalPlaces;
    employeeNameInput.value = employeeName;

    // Načítaj work data z localStorage
    loadFromLocalStorage();

    showSaveNotification("📴 Offline režim: Data načítané z lokálneho úložiska", "warning");
  } catch (error) {
    console.error('[Offline Mode] Chyba pri načítavaní:', error);
    showSaveNotification("Chyba pri načítavaní offline dát", "error");
  }
}

// Detekcia online/offline stavu
window.addEventListener('online', () => {
  localStorage.setItem('offlineMode', 'false');
  showSaveNotification("✅ Online: Pripojenie obnovené", "success");
  // Reload stránku aby sa Firebase znova pripojil
  setTimeout(() => location.reload(), 1000);
});

window.addEventListener('offline', () => {
  localStorage.setItem('offlineMode', 'true');
  showSaveNotification("📴 Offline režim aktivovaný", "warning");
});

// Utility funkcie
function showSaveNotification(message, type = 'success') {
  const notification = document.getElementById('saveNotification');
  notification.textContent = message;
  notification.className = 'show';
  if (type === 'error') {
    notification.classList.add('error');
  } else if (type === 'warning') {
    notification.classList.add('warning');
  }
  setTimeout(() => notification.classList.remove('show'), 3000);
}

function getFirstName(fullName) {
  if (!fullName || typeof fullName !== 'string') return '';
  const trimmedName = fullName.trim();
  if (!trimmedName) return '';
  const parts = trimmedName.split(' ');
  return parts[0];
}

function updateWelcomeMessage() {
  const welcomeElement = document.getElementById('welcomeMessage');
  if (!welcomeElement) return;
  const firstName = getFirstName(employeeName);
  if (firstName) {
    welcomeElement.textContent = `Vitaj späť, ${firstName}! 👋`;
  } else {
    welcomeElement.textContent = '';
  }
}

// VYLEPŠENÝ Firestore Listener s ochranou pred vymazávaním
function setupFirestoreListener() {
  if (firestoreListenerUnsubscribe) {
    firestoreListenerUnsubscribe();
    firestoreListenerUnsubscribe = null;
  }

  const uid = auth.currentUser?.uid;
  if (!uid) return;

  if (currentMonth === undefined || currentMonth === null || currentYear === undefined || currentYear === null) {
    const now = new Date();
    currentMonth = currentMonth ?? now.getMonth();
    currentYear = currentYear ?? now.getFullYear();
  }

  const yearMonthKey = `${currentYear}-${currentMonth}`;
  const docRef = doc(db, "users", uid, "calculatorData", yearMonthKey);

  firestoreListenerUnsubscribe = onSnapshot(docRef, (docSnap) => {
    const hasPending = docSnap.metadata.hasPendingWrites;
    const activeElementId = document.activeElement?.id;

    // DÔLEŽITÉ: Ak doc neexistuje a snapshot je z cache / sme offline,
    // NESMIEME prepisovať localStorage prázdnymi dátami.
    if (!docSnap.exists() && (docSnap.metadata.fromCache || !navigator.onLine)) {
      return;
    }

    // Ak ide o náš vlastný zápis, neaktualizujeme UI
    if (hasPending) {
      if (docSnap.exists()) {
        const data = docSnap.data();
        const firebaseDaysData = data.days || [];
        if (!monthData) monthData = {};
        if (!monthData[currentYear]) monthData[currentYear] = {};
        monthData[currentYear][currentMonth] = firebaseDaysData.map(day => ({
          start: day.start || '',
          end: day.end || '',
          breakTime: day.breakTime || '',
          note: day.note || '',
          noteVisible: day.noteVisible === true
        }));

        // Ulož aj pending dáta do localStorage (bez triggerovania Firebase)
        saveToLocalStorage(true);
      }
      return;
    }

    // NOVÁ LOGIKA: Ak používateľ aktívne edituje, odložíme sync
    if (isUserEditing || pendingChanges.size > 0) {
      return;
    }

    // Overíme timestamp - ak je lokálna zmena čerstvejšia, ignorujeme Firebase
    const firestoreTimestamp = docSnap.data()?.timestamp?.toMillis() || 0;
    if (localChangeTimestamp > firestoreTimestamp && (Date.now() - localChangeTimestamp < 5000)) {
      return;
    }

    if (docSnap.exists()) {
      const data = docSnap.data();
      try {
        const firebaseHourlyWage = data.hourlyWage ?? hourlyWage;
        const firebaseTaxRatePercent = data.taxRate ?? (taxRate * 100);
        const firebaseDecimalPlaces = data.decimalPlaces ?? decimalPlaces;
        const firebaseEmployeeName = data.employeeName ?? employeeName;
        const firebaseDarkMode = data.darkMode ?? document.body.classList.contains('dark-mode');
        const firebaseDaysData = data.days || [];

        hourlyWage = firebaseHourlyWage;
        taxRate = firebaseTaxRatePercent / 100;
        decimalPlaces = firebaseDecimalPlaces;
        employeeName = firebaseEmployeeName;

        if (document.activeElement !== hourlyWageInput) { hourlyWageInput.value = hourlyWage; }
        if (document.activeElement !== taxRateInput) { taxRateInput.value = taxRate * 100; }
        decimalPlacesSelect.value = decimalPlaces;
        if (document.activeElement !== employeeNameInput) { employeeNameInput.value = employeeName; }

        if (!monthData) monthData = {};
        if (!monthData[currentYear]) monthData[currentYear] = {};
        
        // NOVÁ LOGIKA: Merge namiesto prepísania
        // Použitie ?? (nullish coalescing) - prázdny string '' sa správne uloží
        const existingData = monthData[currentYear][currentMonth] || [];
        monthData[currentYear][currentMonth] = firebaseDaysData.map((day, idx) => {
          const existing = existingData[idx] || {};
          return {
            start: day.start ?? existing.start ?? '',
            end: day.end ?? existing.end ?? '',
            breakTime: day.breakTime ?? existing.breakTime ?? '',
            note: day.note ?? existing.note ?? '',
            noteVisible: day.noteVisible ?? existing.noteVisible ?? false
          };
        });

        const daysInMonth = getDaysInMonth(currentMonth);
        let anyRowRecalculated = false;

        for (let i = 1; i <= daysInMonth; i++) {
          const dayIndex = i - 1;
          const firebaseDayData = monthData[currentYear]?.[currentMonth]?.[dayIndex] || {
            start: '', end: '', breakTime: '', note: '', noteVisible: false
          };

          const startId = `start-${currentYear}-${currentMonth}-${i}`;
          const endId = `end-${currentYear}-${currentMonth}-${i}`;
          const breakId = `break-${currentYear}-${currentMonth}-${i}`;
          const noteId = `note-${currentYear}-${currentMonth}-${i}`;
          const noteContainerId = `note-container-${currentYear}-${currentMonth}-${i}`;
          const noteButtonId = `note-toggle-${currentYear}-${currentMonth}-${i}`;
          const noteIndicatorId = `note-indicator-${currentYear}-${currentMonth}-${i}`;

          const startElement = document.getElementById(startId);
          const endElement = document.getElementById(endId);
          const breakElement = document.getElementById(breakId);
          const noteElement = document.getElementById(noteId);
          const noteContainer = document.getElementById(noteContainerId);
          const noteButton = document.getElementById(noteButtonId);
          const noteIndicator = document.getElementById(noteIndicatorId);

          if (startElement && endElement && breakElement && noteElement && noteContainer && noteButton && noteIndicator) {
            const newStart = firebaseDayData.start || '';
            const newEnd = firebaseDayData.end || '';
            const newBreak = firebaseDayData.breakTime || '';
            const newNote = firebaseDayData.note || '';
            const newNoteVisible = firebaseDayData.noteVisible === true;
            let rowUpdatedByListener = false;

            // VYLEPŠENÉ: Neprepisuj ak je pole práve editované
            if (startElement.value !== newStart && activeElementId !== startId && !pendingChanges.has(startId)) {
              startElement.value = newStart;
              rowUpdatedByListener = true;
            }
            if (endElement.value !== newEnd && activeElementId !== endId && !pendingChanges.has(endId)) {
              endElement.value = newEnd;
              rowUpdatedByListener = true;
            }
            if (breakElement.value !== newBreak && activeElementId !== breakId && !pendingChanges.has(breakId)) {
              breakElement.value = newBreak;
              rowUpdatedByListener = true;
            }
            if (noteElement.value !== newNote && activeElementId !== noteId && !pendingChanges.has(noteId)) {
              noteElement.value = newNote;
              updateNoteIndicator(i);
            }

            const currentNoteVisible = noteContainer.classList.contains('visible');
            if (currentNoteVisible !== newNoteVisible) {
              noteContainer.classList.toggle('visible', newNoteVisible);
              noteButton.textContent = newNoteVisible ? 'Skryť' : 'Poznámka';
            }

            if (rowUpdatedByListener) {
              calculateRow(i);
              anyRowRecalculated = true;
            }
          }
        }

        if (anyRowRecalculated) { calculateTotal(); }
        applyDarkMode(firebaseDarkMode);
        updateWelcomeMessage();
        updateDataSize();

        // DÔLEŽITÉ: Ulož do localStorage aby boli dáta dostupné v offline režime
        saveToLocalStorage(true);

        // Notify sync only when server-confirmed (avoid local/pending snapshot spam)
        if (!docSnap.metadata.hasPendingWrites && !docSnap.metadata.fromCache) {
          showSaveNotification("✅ Dáta synchronizované", "success");
        }

      } catch (processError) {
        console.error(`Listener: Chyba pri spracovaní dát:`, processError);
        showSaveNotification("Chyba: Nesprávny formát dát z Firebase", "error");
      }
    } else {
      // Document neexistuje v Firestore
      // Skontroluj, či už máme lokálne dáta - ak áno, NEMAŽ ich
      let localData = {};
      try {
        const storedMonthData = localStorage.getItem('workDaysData');
        localData = storedMonthData ? JSON.parse(storedMonthData) : {};
      } catch (e) {
        console.error('[Firestore] Chyba pri parsovaní workDaysData z localStorage:', e);
        localData = {};
      }

      const hasLocalDataForMonth =
        localData?.[currentYear]?.[currentMonth] &&
        Array.isArray(localData[currentYear][currentMonth]) &&
        localData[currentYear][currentMonth].length > 0;

      if (!monthData) monthData = {};
      if (!monthData[currentYear]) monthData[currentYear] = {};

      // Nastav prázdny mesiac len ak:
      // 1. Ide o server-confirmed stav (!fromCache)
      // 2. A lokálne pre tento mesiac ešte nemáme žiadne dáta
      if (!docSnap.metadata.fromCache && !hasLocalDataForMonth) {
        monthData[currentYear][currentMonth] = [];
        localStorage.setItem('workDaysData', JSON.stringify(monthData));
      } else if (hasLocalDataForMonth) {
        // Máme lokálne dáta - použijeme ich namiesto prázdneho poľa
        monthData[currentYear][currentMonth] = localData[currentYear][currentMonth];
      } else {
        // fromCache a žiadne lokálne dáta - nedotkneme sa localStorage
        monthData[currentYear][currentMonth] = monthData[currentYear][currentMonth] || [];
      }

      let hourlyWageLS = 10, taxRateLS = 0.02, darkModeLS = false, decimalPlacesLS = 1, employeeNameLS = '';
      try {
        hourlyWageLS = parseFloat(JSON.parse(localStorage.getItem('hourlyWage'))) || 10;
        taxRateLS = parseFloat(JSON.parse(localStorage.getItem('taxRate'))) / 100 || 0.02;
        darkModeLS = JSON.parse(localStorage.getItem('darkMode')) || false;
        decimalPlacesLS = parseInt(JSON.parse(localStorage.getItem('decimalPlaces'))) || 1;
        employeeNameLS = JSON.parse(localStorage.getItem('employeeName')) || '';
      } catch (e) {
        console.error('[Firestore] Chyba pri parsovaní nastavení z localStorage:', e);
      }

      hourlyWage = hourlyWageLS;
      taxRate = taxRateLS;
      decimalPlaces = decimalPlacesLS;
      employeeName = employeeNameLS;

      hourlyWageInput.value = hourlyWage;
      taxRateInput.value = taxRate * 100;
      decimalPlacesSelect.value = decimalPlaces;
      employeeNameInput.value = employeeName;

      createTable();
      calculateTotal();
      applyDarkMode(darkModeLS);
      updateWelcomeMessage();
      updateDataSize();
    }

  }, (error) => {
    const safeMessage = handleFirestoreError(error, 'listener');
    showSaveNotification(safeMessage, "error");
    loadFromLocalStorage();
  });
}

// VYLEPŠENÉ ukladanie do Firebase
async function saveToFirebase() {
  const currentUser = auth.currentUser;
  if (!currentUser) return;
  
  try {
    localChangeTimestamp = Date.now(); // Zaznamenaj čas lokálnej zmeny

    const currentMonthWorkData = ((monthData && monthData[currentYear] && monthData[currentYear][currentMonth]) || []).map(day => ({
      start: day.start || '',
      end: day.end || '',
      breakTime: day.breakTime || '',
      note: day.note || '',
      noteVisible: day.noteVisible === true
    }));

    const dataToSave = {
      days: currentMonthWorkData,
      hourlyWage: hourlyWage || 10,
      taxRate: (taxRate * 100) || 2,
      decimalPlaces: decimalPlaces || 1,
      employeeName: employeeName || '',
      darkMode: document.body.classList.contains('dark-mode'),
      timestamp: serverTimestamp()
    };

    const yearMonthDoc = `${currentYear}-${currentMonth}`;
    const uid = currentUser.uid;
    const docRef = doc(db, "users", uid, "calculatorData", yearMonthDoc);

    await setDoc(docRef, dataToSave);

  } catch (error) {
    const safeMessage = handleFirestoreError(error, 'ukladanie');
    showSaveNotification(safeMessage, "error");
  }
}

// VYLEPŠENÉ ukladanie do Local Storage
let saveTimeout = null;
function saveToLocalStorage(skipFirebase = false) {
  try {
    if (!monthData) monthData = {};
    if (!monthData[currentYear]) monthData[currentYear] = {};
    if (!monthData[currentYear][currentMonth]) {
      monthData[currentYear][currentMonth] = [];
    }

    localStorage.setItem('hourlyWage', JSON.stringify(hourlyWage));
    localStorage.setItem('taxRate', JSON.stringify(taxRate * 100));
    localStorage.setItem('darkMode', JSON.stringify(document.body.classList.contains('dark-mode')));
    localStorage.setItem('decimalPlaces', JSON.stringify(decimalPlaces));
    localStorage.setItem('employeeName', JSON.stringify(employeeName));
    localStorage.setItem('currentMonth', currentMonth.toString());
    localStorage.setItem('currentYear', currentYear.toString());

    const serializedMonthData = JSON.stringify(monthData);
    const bytes = new Blob([serializedMonthData]).size;

    if (bytes > MAX_DATA_SIZE * 0.9) {
      console.warn(`Veľkosť dát v localStorage sa blíži k limitu: ${bytes} bajtov`);
    }
    if (bytes > MAX_DATA_SIZE) {
      alert(`Prekročili ste maximálnu veľkosť dát (~${MAX_DATA_SIZE_KB} KB).`);
      showSaveNotification("Chyba: Lokálne dáta sú príliš veľké!", "error");
      return;
    }

    localStorage.setItem('workDaysData', serializedMonthData);
    updateDataSize();

    // Debounce Firebase save - SKIP ak volané z Firebase listenera
    if (!skipFirebase) {
      if (saveTimeout) clearTimeout(saveTimeout);
      saveTimeout = setTimeout(() => {
        saveToFirebase();
        if (!navigator.onLine) {
          showSaveNotification("Offline: Zmeny uložené lokálne", "warning");
        }
      }, 1000);
    }

  } catch (error) {
    console.error('Chyba pri ukladaní:', error);
    showSaveNotification("Kritická chyba pri ukladaní!", "error");
  }
}

function loadFromLocalStorage() {
  try {
    if (currentMonth === undefined || currentMonth === null || currentYear === undefined || currentYear === null) {
      const storedMonth = localStorage.getItem('currentMonth');
      const storedYear = localStorage.getItem('currentYear');
      const currentDate = new Date();
      currentMonth = storedMonth !== null ? parseInt(storedMonth) : currentDate.getMonth();
      currentYear = storedYear !== null ? parseInt(storedYear) : currentDate.getFullYear();
    }

    const storedMonthData = localStorage.getItem('workDaysData');
    monthData = storedMonthData ? JSON.parse(storedMonthData) : {};

    if (monthData && monthData[currentYear] && monthData[currentYear][currentMonth]) {
      monthData[currentYear][currentMonth] = monthData[currentYear][currentMonth].map(day => ({
        ...day,
        noteVisible: day.noteVisible === true
      }));
    }

    hourlyWage = parseFloat(JSON.parse(localStorage.getItem('hourlyWage'))) || 10;
    taxRate = parseFloat(JSON.parse(localStorage.getItem('taxRate'))) / 100 || 0.02;
    const darkMode = JSON.parse(localStorage.getItem('darkMode')) || false;
    decimalPlaces = parseInt(JSON.parse(localStorage.getItem('decimalPlaces'))) || 1;
    employeeName = JSON.parse(localStorage.getItem('employeeName')) || '';
    
    updateUIFromLoadedData(darkMode);
  } catch (error) {
    console.error(`Chyba pri načítavaní dát:`, error);
    showSaveNotification("Chyba pri načítaní lokálnych dát!", "error");
    monthData = {};
    createTable();
    calculateTotal();
  }
}

function updateUIFromLoadedData(darkModeValue) {
  try {
    hourlyWageInput.value = hourlyWage;
    taxRateInput.value = taxRate * 100;
    decimalPlacesSelect.value = decimalPlaces;
    employeeNameInput.value = employeeName;

    if (monthSelect.querySelector(`option[value="${currentMonth}"]`)) {
      monthSelect.value = currentMonth;
    } else {
      monthSelect.value = new Date().getMonth();
      currentMonth = parseInt(monthSelect.value);
    }

    if (yearSelect.querySelector(`option[value="${currentYear}"]`)) {
      yearSelect.value = currentYear;
    } else {
      yearSelect.value = new Date().getFullYear();
      currentYear = parseInt(yearSelect.value);
      populateYearSelect();
      yearSelect.value = currentYear;
    }

    createTable();
    const dataForCurrentMonth = (monthData && monthData[currentYear] && monthData[currentYear][currentMonth]) || [];

    dataForCurrentMonth.forEach((day, index) => {
      const i = index + 1;
      const startElement = document.getElementById(`start-${currentYear}-${currentMonth}-${i}`);
      const endElement = document.getElementById(`end-${currentYear}-${currentMonth}-${i}`);
      const breakElement = document.getElementById(`break-${currentYear}-${currentMonth}-${i}`);
      const noteElement = document.getElementById(`note-${currentYear}-${currentMonth}-${i}`);
      const noteContainer = document.getElementById(`note-container-${currentYear}-${currentMonth}-${i}`);
      const noteButton = document.getElementById(`note-toggle-${currentYear}-${currentMonth}-${i}`);
      const noteIndicator = document.getElementById(`note-indicator-${currentYear}-${currentMonth}-${i}`);

      if (startElement && endElement && breakElement && noteElement && noteContainer && noteButton && noteIndicator) {
        startElement.value = day.start || '';
        endElement.value = day.end || '';
        breakElement.value = day.breakTime || '';
        noteElement.value = day.note || '';
        calculateRow(i);

        const isNoteVisible = day.noteVisible === true;
        noteContainer.classList.toggle('visible', isNoteVisible);
        noteButton.textContent = isNoteVisible ? 'Skryť' : 'Poznámka';
        updateNoteIndicator(i);

        const isDarkModeActive = document.body.classList.contains('dark-mode');
        if (noteElement) noteElement.classList.toggle('dark-mode', isDarkModeActive);
        if (noteButton) noteButton.classList.toggle('dark-mode', isDarkModeActive);
        if (noteIndicator) noteIndicator.classList.toggle('dark-mode', isDarkModeActive);
      }
    });

    calculateTotal();
    updateDataSize();
    applyDarkMode(darkModeValue);
    updateWelcomeMessage();
  } catch (error) {
    console.error("Chyba počas aktualizácie UI:", error);
    showSaveNotification("Chyba pri prekresľovaní UI!", "error");
  }
}

function applyDarkMode(isDark) {
  const elementsToToggle = [
    document.body,
    document.querySelector('.container'),
    totalSalaryDiv,
    document.querySelector('.collapsible-settings summary'),
    ...document.querySelectorAll('table, th, td'),
    ...document.querySelectorAll('input[type="tel"], input[type="number"], input[type="text"], select'),
    ...document.querySelectorAll('.btn'),
    ...document.querySelectorAll('.toggle-note-btn'),
    ...document.querySelectorAll('.note-textarea'),
    ...document.querySelectorAll('.time-icon'),
    ...document.querySelectorAll('.note-indicator-icon')
  ];
  
  elementsToToggle.forEach(el => el?.classList[isDark ? 'add' : 'remove']('dark-mode'));
  
  const currentDayRow = document.querySelector('.current-day');
  if (currentDayRow) {
    currentDayRow.classList[isDark ? 'add' : 'remove']('dark-mode');
    currentDayRow.querySelectorAll('input, .note-textarea, .toggle-note-btn').forEach(el => 
      el?.classList[isDark ? 'add' : 'remove']('dark-mode')
    );
  }
}

function getDayName(year, month, day) {
  const daysOfWeek = ["Nedeľa", "Pondelok", "Utorok", "Streda", "Štvrtok", "Piatok", "Sobota"];
  return daysOfWeek[new Date(year, month, day).getDay()];
}

function createTable() {
  workDays.replaceChildren();
  const daysInMonth = getDaysInMonth(currentMonth);
  const today = new Date();
  const currentDayOfMonth = today.getDate();
  const currentMonthIndex = today.getMonth();
  const currentYearValue = today.getFullYear();

  for (let i = 1; i <= daysInMonth; i++) {
    const row = document.createElement('tr');
    if (i === currentDayOfMonth && currentMonth === currentMonthIndex && currentYear === currentYearValue) {
      row.classList.add('current-day');
    }

    const dayName = getDayName(currentYear, currentMonth, i);
    const baseId = `${currentYear}-${currentMonth}-${i}`;
    const startId = `start-${baseId}`;
    const endId = `end-${baseId}`;
    const breakId = `break-${baseId}`;
    const totalId = `total-${baseId}`;
    const grossId = `gross-${baseId}`;
    const netId = `net-${baseId}`;
    const noteToggleId = `note-toggle-${baseId}`;
    const noteContainerId = `note-container-${baseId}`;
    const noteTextareaId = `note-${baseId}`;
    const noteIndicatorId = `note-indicator-${baseId}`;

    // TD 1: Deň
    const td1 = document.createElement('td');
    td1.textContent = `Deň ${i} (${dayName})`;

    // TD 2: Príchod
    const td2 = document.createElement('td');
    const startInput = document.createElement('input');
    startInput.type = 'tel';
    startInput.id = startId;
    startInput.setAttribute('maxlength', '5');
    startInput.setAttribute('pattern', '[0-9:]*');
    startInput.setAttribute('inputmode', 'numeric');
    startInput.placeholder = 'HH:MM';
    startInput.dataset.day = i;
    startInput.dataset.field = 'start';
    startInput.dataset.nextField = endId;

    const startIcon = document.createElement('span');
    startIcon.className = 'time-icon';
    startIcon.title = 'Vložiť aktuálny čas';
    startIcon.textContent = '⏰';
    startIcon.dataset.action = 'insert-time';
    startIcon.dataset.target = startId;

    td2.appendChild(startInput);
    td2.appendChild(startIcon);

    // TD 3: Odchod
    const td3 = document.createElement('td');
    const endInput = document.createElement('input');
    endInput.type = 'tel';
    endInput.id = endId;
    endInput.setAttribute('maxlength', '5');
    endInput.setAttribute('pattern', '[0-9:]*');
    endInput.setAttribute('inputmode', 'numeric');
    endInput.placeholder = 'HH:MM';
    endInput.dataset.day = i;
    endInput.dataset.field = 'end';
    endInput.dataset.nextField = breakId;

    const endIcon = document.createElement('span');
    endIcon.className = 'time-icon';
    endIcon.title = 'Vložiť aktuálny čas';
    endIcon.textContent = '⏰';
    endIcon.dataset.action = 'insert-time';
    endIcon.dataset.target = endId;

    td3.appendChild(endInput);
    td3.appendChild(endIcon);

    // TD 4: Prestávka
    const td4 = document.createElement('td');
    const breakInput = document.createElement('input');
    breakInput.type = 'number';
    breakInput.id = breakId;
    breakInput.setAttribute('min', '0');
    breakInput.setAttribute('step', '0.5');
    breakInput.placeholder = 'prestávka';
    breakInput.dataset.day = i;
    breakInput.dataset.field = 'breakTime';
    td4.appendChild(breakInput);

    // TD 5: Odpracované
    const td5 = document.createElement('td');
    td5.id = totalId;
    td5.textContent = `0h 0m (${(0).toFixed(decimalPlaces || 1)} h)`;

    // TD 6: Hrubá Mzda
    const td6 = document.createElement('td');
    const grossInput = document.createElement('input');
    grossInput.type = 'number';
    grossInput.id = grossId;
    grossInput.setAttribute('min', '0');
    grossInput.setAttribute('step', '0.01');
    grossInput.placeholder = 'Hrubá Mzda';
    grossInput.readOnly = true;
    td6.appendChild(grossInput);

    // TD 7: Čistá Mzda
    const td7 = document.createElement('td');
    const netInput = document.createElement('input');
    netInput.type = 'number';
    netInput.id = netId;
    netInput.setAttribute('min', '0');
    netInput.setAttribute('step', '0.01');
    netInput.placeholder = 'Čistá Mzda';
    netInput.readOnly = true;
    td7.appendChild(netInput);

    // TD 8: Poznámka
    const td8 = document.createElement('td');

    const noteIndicator = document.createElement('span');
    noteIndicator.className = 'note-indicator-icon';
    noteIndicator.id = noteIndicatorId;
    noteIndicator.textContent = '📝';
    noteIndicator.style.display = 'none';

    const noteToggleBtn = document.createElement('button');
    noteToggleBtn.type = 'button';
    noteToggleBtn.id = noteToggleId;
    noteToggleBtn.className = 'toggle-note-btn';
    noteToggleBtn.textContent = 'Poznámka';
    noteToggleBtn.dataset.action = 'toggle-note';
    noteToggleBtn.dataset.day = i;

    const noteContainer = document.createElement('div');
    noteContainer.id = noteContainerId;
    noteContainer.className = 'note-container';

    const noteTextarea = document.createElement('textarea');
    noteTextarea.id = noteTextareaId;
    noteTextarea.className = 'note-textarea';
    noteTextarea.placeholder = 'Zadajte poznámku...';
    noteTextarea.dataset.day = i;
    noteTextarea.dataset.field = 'note';

    noteContainer.appendChild(noteTextarea);
    td8.appendChild(noteIndicator);
    td8.appendChild(noteToggleBtn);
    td8.appendChild(noteContainer);

    // TD 9: Reset
    const td9 = document.createElement('td');
    const resetBtn = document.createElement('button');
    resetBtn.type = 'button';
    resetBtn.className = 'btn reset-btn';
    resetBtn.textContent = 'Vynulovať';
    resetBtn.dataset.action = 'reset-row';
    resetBtn.dataset.day = i;
    td9.appendChild(resetBtn);

    row.appendChild(td1);
    row.appendChild(td2);
    row.appendChild(td3);
    row.appendChild(td4);
    row.appendChild(td5);
    row.appendChild(td6);
    row.appendChild(td7);
    row.appendChild(td8);
    row.appendChild(td9);

    workDays.appendChild(row);
  }

  applyDarkMode(document.body.classList.contains('dark-mode'));
}

window.insertCurrentTime = function(targetInputId) {
  const now = new Date();
  const hours = now.getHours().toString().padStart(2, '0');
  const minutes = now.getMinutes().toString().padStart(2, '0');
  const formattedTime = `${hours}:${minutes}`;

  const targetInput = document.getElementById(targetInputId);
  if (targetInput) {
    targetInput.value = formattedTime;
    const day = parseInt(targetInputId.split('-')[3]);
    if (!isNaN(day)) {
      updateMonthDataFromInput(targetInput, day);
      calculateRow(day);
      calculateTotal();
      saveToLocalStorage();
    }
  }
}

function toggleNote(day) {
  const containerId = `note-container-${currentYear}-${currentMonth}-${day}`;
  const buttonId = `note-toggle-${currentYear}-${currentMonth}-${day}`;
  const noteContainer = document.getElementById(containerId);
  const toggleButton = document.getElementById(buttonId);

  if (noteContainer && toggleButton) {
    const isVisible = noteContainer.classList.toggle('visible');
    toggleButton.textContent = isVisible ? 'Skryť' : 'Poznámka';

    const dayIndex = day - 1;
    if (monthData && monthData[currentYear] && monthData[currentYear][currentMonth] && monthData[currentYear][currentMonth][dayIndex]) {
      monthData[currentYear][currentMonth][dayIndex].noteVisible = isVisible;
    } else {
      if (!monthData) monthData = {};
      if (!monthData[currentYear]) monthData[currentYear] = {};
      if (!monthData[currentYear][currentMonth]) monthData[currentYear][currentMonth] = [];
      while (dayIndex >= monthData[currentYear][currentMonth].length) {
        monthData[currentYear][currentMonth].push({
          start: '', end: '', breakTime: '', note: '', noteVisible: false
        });
      }
      monthData[currentYear][currentMonth][dayIndex].noteVisible = isVisible;
    }
    
    saveToLocalStorage();

    if (document.body.classList.contains('dark-mode')) {
      const textarea = noteContainer.querySelector('textarea');
      if (textarea) textarea.classList.toggle('dark-mode', isVisible);
      toggleButton.classList.toggle('dark-mode', isVisible);
    }
  }
}

function updateNoteIndicator(day) {
  const noteTextarea = document.getElementById(`note-${currentYear}-${currentMonth}-${day}`);
  const indicatorIcon = document.getElementById(`note-indicator-${currentYear}-${currentMonth}-${day}`);
  
  if (noteTextarea && indicatorIcon) {
    const hasContent = noteTextarea.value.trim() !== '';
    indicatorIcon.style.display = hasContent ? 'inline-block' : 'none';
    indicatorIcon.classList.toggle('dark-mode', document.body.classList.contains('dark-mode'));
  }
}

function isTimeValid(timeStr) {
  return VALIDATION_RULES.TIME_REGEX.test(timeStr);
}

// VYLEPŠENÉ input handling s ochranou
function handleInput(input, nextId, day) {
  // Označ že pole sa edituje
  isUserEditing = true;
  pendingChanges.add(input.id);

  if (editingTimeout) clearTimeout(editingTimeout);
  editingTimeout = setTimeout(() => {
    isUserEditing = false;
    pendingChanges.delete(input.id);
  }, 2000);

  formatInput(input);

  // Validácia času pre tel inputy
  if (input.type === 'tel' && input.value.trim() !== '') {
    const timeValidation = validateTime(input.value);
    if (!timeValidation.valid) {
      showValidationError(input, timeValidation.error);
      // Pokračuj s uložením aj napriek chybe (user môže opraviť neskôr)
    } else {
      clearValidationError(input);
    }
  }

  updateMonthDataFromInput(input, day);
  calculateRow(day);
  calculateTotal();
  saveToLocalStorage();

  // Akceptuje 4 znaky ("8:30") aj 5 znakov ("08:30")
  if (input.type === 'tel' && input.value.length >= 4 && input.value.length <= 5 && isTimeValid(input.value)) {
    moveNext(input, nextId);
  }
}

function handleBreakInput(day) {
  const input = document.getElementById(`break-${currentYear}-${currentMonth}-${day}`);
  isUserEditing = true;
  pendingChanges.add(input.id);

  if (editingTimeout) clearTimeout(editingTimeout);
  editingTimeout = setTimeout(() => {
    isUserEditing = false;
    pendingChanges.delete(input.id);
  }, 2000);

  // Validácia prestávky
  if (input.value.trim() !== '') {
    const breakValidation = validateNumber(
      input.value,
      0,
      VALIDATION_RULES.MAX_BREAK_HOURS,
      'Prestávka'
    );
    if (!breakValidation.valid) {
      showValidationError(input, breakValidation.error);
    } else {
      clearValidationError(input);
    }
  }

  updateMonthDataFromInput(input, day);
  calculateRow(day);
  calculateTotal();
  saveToLocalStorage();
}

function handleNoteInput(textarea, day) {
  isUserEditing = true;
  pendingChanges.add(textarea.id);

  if (editingTimeout) clearTimeout(editingTimeout);
  editingTimeout = setTimeout(() => {
    isUserEditing = false;
    pendingChanges.delete(textarea.id);
  }, 2000);

  // Validácia poznámky (length limit)
  const noteValidation = validateNote(textarea.value);
  if (!noteValidation.valid) {
    showValidationError(textarea, noteValidation.error);
    // Automaticky skráť poznámku na max dĺžku
    textarea.value = noteValidation.value;
  } else {
    clearValidationError(textarea);
  }

  // Zobraz počítadlo znakov (voliteľné)
  updateNoteCharacterCount(textarea, noteValidation.length);

  updateMonthDataFromInput(textarea, day);
  saveToLocalStorage();
  updateNoteIndicator(day);
}

// Helper funkcia pre zobrazenie počítadla znakov
function updateNoteCharacterCount(textarea, length) {
  // Môžeme pridať counter element vedľa textarea (voliteľné)
  const maxLength = VALIDATION_RULES.MAX_NOTE_LENGTH;
  if (length > maxLength * 0.9) {
    // Varovanie ak je blízko limitu
    textarea.title = `Poznámka: ${length}/${maxLength} znakov`;
  } else {
    textarea.title = '';
  }
}

function updateMonthDataFromInput(input, day) {
  if (!input) return;
  
  const dayIndex = day - 1;
  const fieldId = input.id;
  let field = 'unknown';

  if (fieldId.startsWith('start-')) field = 'start';
  else if (fieldId.startsWith('end-')) field = 'end';
  else if (fieldId.startsWith('break-')) field = 'breakTime';
  else if (fieldId.startsWith('note-')) field = 'note';

  const value = input.value;

  if (field !== 'unknown') {
    if (!monthData) monthData = {};
    if (!monthData[currentYear]) monthData[currentYear] = {};
    if (!monthData[currentYear][currentMonth]) monthData[currentYear][currentMonth] = [];

    while (dayIndex >= monthData[currentYear][currentMonth].length) {
      monthData[currentYear][currentMonth].push({
        start: '', end: '', breakTime: '', note: '', noteVisible: false
      });
    }

    if (monthData[currentYear][currentMonth][dayIndex] && typeof monthData[currentYear][currentMonth][dayIndex].noteVisible === 'undefined') {
      monthData[currentYear][currentMonth][dayIndex].noteVisible = false;
    }

    if (!monthData[currentYear][currentMonth][dayIndex]) {
      monthData[currentYear][currentMonth][dayIndex] = {
        start: '', end: '', breakTime: '', note: '', noteVisible: false
      };
    }

    const currentValue = monthData[currentYear]?.[currentMonth]?.[dayIndex]?.[field];
    if (currentValue !== value) {
      monthData[currentYear][currentMonth][dayIndex][field] = value;
    }
  }
}

function formatInput(input) {
  if (!input || input.type !== 'tel') return;
  
  let value = input.value.replace(/[^\d:]/g, '');

  // 4 číslice bez dvojbodky: "0830" → "08:30", "1800" → "18:00"
  if (value.length === 4 && !value.includes(':')) {
    value = value.slice(0, 2) + ':' + value.slice(2);
  }
  // 3 číslice bez dvojbodky: "830" → "8:30" (len ak sú minúty platné 00-59)
  // "180" sa neformátuje (80 > 59), počká sa na 4. číslicu → "1800" → "18:00"
  // "110" sa neformátuje - prvá číslica "1" môže byť začiatok 10:xx - 19:xx
  // "230" sa neformátuje - "23" je platná hodina, počká sa na "2300" → "23:00"
  else if (value.length === 3 && !value.includes(':')) {
    const firstDigit = value[0];
    const secondDigit = value[1];
    const minutes = parseInt(value.slice(1), 10);

    // Neformátuj ak prvá číslica je "1" (môže byť 10:xx - 19:xx)
    // Neformátuj ak prvé dve číslice sú 20-23 (platné 2-ciferné hodiny)
    const couldBeTwoDigitHour = firstDigit === '1' ||
      (firstDigit === '2' && secondDigit >= '0' && secondDigit <= '3');

    if (!couldBeTwoDigitHour && minutes <= 59) {
      value = value.slice(0, 1) + ':' + value.slice(1);
    }
  }

  if (value.length > 5) {
    value = value.slice(0, 5);
  }

  if (input.value !== value) {
    input.value = value;
  }

  // Validácia: akceptuje "8:30" (4 znaky) aj "08:30" (5 znakov)
  if (value.length > 0 && value.length < 4) {
    // Ešte píše, nič nekontroluj
    if (input.style.border !== '') input.style.border = '';
  } else if (value.length >= 4 && value.length <= 5) {
    if (isTimeValid(value)) {
      if (input.style.border !== '') input.style.border = '';
    } else {
      input.style.border = '1px solid red';
      setTimeout(() => {
        if (input.style.borderColor === 'red') input.style.border = '';
      }, 2000);
    }
  } else {
    if (input.style.border !== '') input.style.border = '';
  }
}

function moveNext(currentElement, nextId) {
  if (!nextId || !currentElement) return;
  const nextElement = document.getElementById(nextId);
  if (nextElement && document.activeElement === currentElement) {
    nextElement.focus();
    if (nextElement.select) nextElement.select();
  }
}

function calculateRow(day) {
  const startTimeStr = document.getElementById(`start-${currentYear}-${currentMonth}-${day}`)?.value;
  const endTimeStr = document.getElementById(`end-${currentYear}-${currentMonth}-${day}`)?.value;
  const breakTimeInput = document.getElementById(`break-${currentYear}-${currentMonth}-${day}`);
  const breakTime = parseFloat(breakTimeInput?.value) || 0;
  const totalCell = document.getElementById(`total-${currentYear}-${currentMonth}-${day}`);
  const grossElement = document.getElementById(`gross-${currentYear}-${currentMonth}-${day}`);
  const netElement = document.getElementById(`net-${currentYear}-${currentMonth}-${day}`);

  if (!totalCell || !grossElement || !netElement) return;

  if (!startTimeStr && !endTimeStr) {
    totalCell.textContent = `0h 0m (${(0).toFixed(decimalPlaces || 1)} h)`;
    grossElement.value = '0.00';
    netElement.value = '0.00';
    return;
  }

  if (!VALIDATION_RULES.TIME_REGEX.test(startTimeStr) && startTimeStr !== '' || !VALIDATION_RULES.TIME_REGEX.test(endTimeStr) && endTimeStr !== '') {
    totalCell.textContent = 'Neplatný čas';
    grossElement.value = '0.00';
    netElement.value = '0.00';
    return;
  }

  if (startTimeStr === '' || endTimeStr === '') {
    totalCell.textContent = `0h 0m (${(0).toFixed(decimalPlaces || 1)} h)`;
    grossElement.value = '0.00';
    netElement.value = '0.00';
    return;
  }

  const [startHours, startMinutes] = startTimeStr.split(':').map(Number);
  const [endHours, endMinutes] = endTimeStr.split(':').map(Number);
  const startTotalMinutes = startHours * 60 + startMinutes;
  let endTotalMinutes = endHours * 60 + endMinutes;

  if (endTotalMinutes < startTotalMinutes) {
    endTotalMinutes += 24 * 60;
  }

  const diffMinutes = endTotalMinutes - startTotalMinutes;
  const breakMinutes = breakTime * 60;
  const workedMinutes = Math.max(0, diffMinutes - breakMinutes);
  const hours = Math.floor(workedMinutes / 60);
  const minutes = Math.round(workedMinutes % 60);
  const decimalHours = (workedMinutes / 60);

  totalCell.textContent = `${hours}h ${minutes}m (${decimalHours.toFixed(decimalPlaces || 1)} h)`;

  const currentHourlyWage = hourlyWage;
  const currentTaxRate = taxRate;
  const grossSalary = decimalHours * currentHourlyWage;
  grossElement.value = isFinite(grossSalary) ? grossSalary.toFixed(2) : '0.00';

  const netSalary = grossSalary * (1 - currentTaxRate);
  netElement.value = isFinite(netSalary) ? netSalary.toFixed(2) : '0.00';
}

function resetRow(day) {
  const dayIndex = day - 1;
  const start = document.getElementById(`start-${currentYear}-${currentMonth}-${day}`);
  const end = document.getElementById(`end-${currentYear}-${currentMonth}-${day}`);
  const breakTime = document.getElementById(`break-${currentYear}-${currentMonth}-${day}`);
  const total = document.getElementById(`total-${currentYear}-${currentMonth}-${day}`);
  const gross = document.getElementById(`gross-${currentYear}-${currentMonth}-${day}`);
  const net = document.getElementById(`net-${currentYear}-${currentMonth}-${day}`);
  const note = document.getElementById(`note-${currentYear}-${currentMonth}-${day}`);
  const noteContainer = document.getElementById(`note-container-${currentYear}-${currentMonth}-${day}`);
  const noteToggle = document.getElementById(`note-toggle-${currentYear}-${currentMonth}-${day}`);
  const noteIndicator = document.getElementById(`note-indicator-${currentYear}-${currentMonth}-${day}`);

  if (start && end && breakTime && total && gross && net && note && noteContainer && noteToggle && noteIndicator) {
    start.value = '';
    end.value = '';
    breakTime.value = '';
    note.value = '';
    total.textContent = `0h 0m (${(0).toFixed(decimalPlaces || 1)} h)`;
    gross.value = '0.00';
    net.value = '0.00';
    noteContainer.classList.remove('visible');
    noteToggle.textContent = 'Poznámka';
    updateNoteIndicator(day);

    if (!monthData) monthData = {};
    if (!monthData[currentYear]) monthData[currentYear] = {};
    if (!monthData[currentYear][currentMonth]) monthData[currentYear][currentMonth] = [];
    
    while (dayIndex >= monthData[currentYear][currentMonth].length) {
      monthData[currentYear][currentMonth].push({
        start: '', end: '', breakTime: '', note: '', noteVisible: false
      });
    }
    
    if (monthData[currentYear][currentMonth][dayIndex]) {
      monthData[currentYear][currentMonth][dayIndex] = {
        start: '', end: '', breakTime: '', note: '', noteVisible: false
      };
    }

    calculateTotal();
    saveToLocalStorage();
  }
}

function resetAll() {
  if (confirm('Naozaj chcete resetovať všetky záznamy pre tento mesiac?')) {
    if (!monthData) monthData = {};
    if (!monthData[currentYear]) monthData[currentYear] = {};
    
    const days = getDaysInMonth(currentMonth);
    monthData[currentYear][currentMonth] = Array.from({ length: days }, () => ({
      start: '', end: '', breakTime: '', note: '', noteVisible: false
    }));

    createTable();
    calculateTotal();
    saveToLocalStorage();
    showSaveNotification("Dáta pre aktuálny mesiac boli resetované.");
  }
}

function calculateTotal() {
  let grandTotalWorkedMinutes = 0;
  let daysWithEntries = 0;
  const rows = workDays.querySelectorAll('tr');
  const currentHourlyWage = hourlyWage;
  const currentTaxRate = taxRate;
  const currentDecimalPlaces = decimalPlaces || 1;

  rows.forEach((row, index) => {
    const dayIndex = index + 1;
    const startTimeStr = document.getElementById(`start-${currentYear}-${currentMonth}-${dayIndex}`)?.value;
    const endTimeStr = document.getElementById(`end-${currentYear}-${currentMonth}-${dayIndex}`)?.value;
    const breakTimeInput = document.getElementById(`break-${currentYear}-${currentMonth}-${dayIndex}`);

    if (startTimeStr && endTimeStr) {
      if (VALIDATION_RULES.TIME_REGEX.test(startTimeStr) && VALIDATION_RULES.TIME_REGEX.test(endTimeStr)) {
        const breakTime = parseFloat(breakTimeInput?.value) || 0;
        const [startHours, startMinutes] = startTimeStr.split(':').map(Number);
        const [endHours, endMinutes] = endTimeStr.split(':').map(Number);
        const startTotalMinutes = startHours * 60 + startMinutes;
        let endTotalMinutes = endHours * 60 + endMinutes;

        if (endTotalMinutes < startTotalMinutes) {
          endTotalMinutes += 24 * 60;
        }

        const diffMinutes = endTotalMinutes - startTotalMinutes;
        const breakMinutes = breakTime * 60;
        const workedMinutesForRow = Math.max(0, diffMinutes - breakMinutes);
        grandTotalWorkedMinutes += workedMinutesForRow;

        if (workedMinutesForRow > 0 || (startTimeStr && endTimeStr)) {
          daysWithEntries++;
        }
      }
    }
  });

  const grandTotalDecimalHours = grandTotalWorkedMinutes / 60;
  const grandTotalGrossSalary = grandTotalDecimalHours * currentHourlyWage;
  const grandTotalNetSalary = grandTotalGrossSalary * (1 - currentTaxRate);
  const averageNetSalary = daysWithEntries > 0 ? (grandTotalNetSalary / daysWithEntries) : 0;
  const averageWorkedMinutes = daysWithEntries > 0 ? grandTotalWorkedMinutes / daysWithEntries : 0;
  const averageHours = Math.floor(averageWorkedMinutes / 60);
  const averageMinutes = Math.round(averageWorkedMinutes % 60);
  const averageDecimalHours = (averageWorkedMinutes / 60);
  const totalHours = Math.floor(grandTotalWorkedMinutes / 60);
  const totalMinutesRemainder = Math.round(grandTotalWorkedMinutes % 60);

  totalSalaryDiv.textContent = `Počet odpracovaných dní: ${daysWithEntries}
Celkový odpracovaný čas: ${totalHours}h ${totalMinutesRemainder}m (${grandTotalDecimalHours.toFixed(currentDecimalPlaces)} h)
Celková hrubá mzda: ${grandTotalGrossSalary.toFixed(2)}€
Celková čistá mzda: ${grandTotalNetSalary.toFixed(2)}€
Priemerná čistá mzda na deň: ${averageNetSalary.toFixed(2)}€
Priemerný odpracovaný čas na deň: ${averageHours}h ${averageMinutes}m (${averageDecimalHours.toFixed(currentDecimalPlaces)} h)`;
}

// ===== KÓD S OPRAVOU DIKRITIKY =====
function exportToPDF() {
  if (typeof window.jspdf === 'undefined' || typeof window.jspdf.jsPDF === 'undefined' || typeof window.jspdf.jsPDF.API.autoTable === 'undefined') {
    alert("Chyba: Knižnica jsPDF alebo autoTable nie je správne načítaná.");
    return;
  }

  const { jsPDF } = window.jspdf;
  try {
    const doc = new jsPDF();
    
    // NOVÉ: Načítanie a nastavenie písma Roboto, ktoré podporuje diakritiku
    try {
      doc.addFont('https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.66/fonts/Roboto/Roboto-Regular.ttf', 'Roboto', 'normal');
      doc.setFont('Roboto');
    } catch (e) {
      console.warn("Nepodarilo sa načítať písmo Roboto pre PDF, použije sa predvolené.", e);
    }

    doc.setFontSize(18);
    doc.text(`Bruno's Calculator - Výkaz (${getMonthName(currentMonth)} ${currentYear})`, 14, 20);
    doc.setFontSize(12);
    doc.text(`Meno pracovníka: ${employeeName || 'Nezadané'}`, 14, 28);
    doc.text(`Hodinová mzda: ${hourlyWage || 'N/A'} €`, 14, 34);
    doc.text(`Daň (%): ${taxRate * 100 || 'N/A'}`, 100, 34);

    const tableColumn = ["Deň", "Príchod", "Odchod", "Prestávka (h)", "Odpracované", "Hrubá Mzda (€)", "Čistá Mzda (€)", "Poznámka"];
    const tableRows = [];
    const dataForCurrentMonth = (monthData && monthData[currentYear] && monthData[currentYear][currentMonth]) || [];

    dataForCurrentMonth.forEach((day, index) => {
      if (day.start || day.end || day.note) {
        const dayNum = index + 1;
        const dayName = getDayName(currentYear, currentMonth, dayNum);
        const totalCell = document.getElementById(`total-${currentYear}-${currentMonth}-${dayNum}`);
        const grossInput = document.getElementById(`gross-${currentYear}-${currentMonth}-${dayNum}`);
        const netInput = document.getElementById(`net-${currentYear}-${currentMonth}-${dayNum}`);
        const workedTimeText = totalCell ? totalCell.textContent : 'N/A';
        const grossValue = grossInput ? parseFloat(grossInput.value).toFixed(2) : '0.00';
        const netValue = netInput ? parseFloat(netInput.value).toFixed(2) : '0.00';
        const noteText = day.note || '';

        const rowData = [
          `Deň ${dayNum} (${dayName})`,
          day.start || '-',
          day.end || '-',
          day.breakTime || '0',
          workedTimeText,
          grossValue,
          netValue,
          noteText
        ];
        tableRows.push(rowData);
      }
    });

    doc.autoTable({
      head: [tableColumn],
      body: tableRows,
      startY: 40,
      // UPRAVENÉ: Pridané nastavenie písma pre tabuľku
      headStyles: { fillColor: [41, 128, 185], textColor: 255, font: doc.getFont().fontName },
      styles: { fontSize: 8, font: doc.getFont().fontName },
      alternateRowStyles: { fillColor: [240, 240, 240] },
      columnStyles: { 7: { cellWidth: 'auto' } }
    });

    const finalY = doc.lastAutoTable.finalY || 40;
    doc.setFontSize(10);
    const totalTextContent = (totalSalaryDiv.textContent || '').split('\n');
    doc.text(totalTextContent, 14, finalY + 10);

    const pdfFileName = `Vykaz-${employeeName || 'pracovnik'}-${getMonthName(currentMonth)}-${currentYear}.pdf`;
    doc.save(pdfFileName);
    showSaveNotification("PDF exportované.");
  } catch (error) {
    console.error("Chyba pri generovaní PDF:", error);
    alert("Nastala chyba pri vytváraní PDF súboru.");
  }
}

// ===== KÓD S OPRAVOU DIKRITIKY =====
function sendPDF() {
  if (typeof window.jspdf === 'undefined' || typeof window.jspdf.jsPDF === 'undefined' || typeof window.jspdf.jsPDF.API.autoTable === 'undefined') {
    alert("Chyba: Knižnica jsPDF alebo autoTable nie je správne načítaná.");
    return;
  }

  const { jsPDF } = window.jspdf;
  try {
    const doc = new jsPDF();

    // NOVÉ: Načítanie a nastavenie písma Roboto, ktoré podporuje diakritiku
    try {
      doc.addFont('https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.66/fonts/Roboto/Roboto-Regular.ttf', 'Roboto', 'normal');
      doc.setFont('Roboto');
    } catch (e) {
      console.warn("Nepodarilo sa načítať písmo Roboto pre PDF, použije sa predvolené.", e);
    }

    doc.setFontSize(16);
    doc.text(`Pracovný výkaz - ${getMonthName(currentMonth)} ${currentYear}`, 14, 20);
    doc.setFontSize(12);
    doc.text(`Meno pracovníka: ${employeeName || 'Nezadané'}`, 14, 28);

    const tableColumn = ["Deň", "Príchod", "Odchod", "Prestávka (h)", "Poznámka"];
    const tableRows = [];
    const dataForCurrentMonth = (monthData && monthData[currentYear] && monthData[currentYear][currentMonth]) || [];

    dataForCurrentMonth.forEach((day, index) => {
      if (day.start || day.end || day.note) {
        const dayNum = index + 1;
        const dayName = getDayName(currentYear, currentMonth, dayNum);
        const noteText = day.note || '';
        const rowData = [
          `Deň ${dayNum} (${dayName})`,
          day.start || '-',
          day.end || '-',
          day.breakTime || '0',
          noteText
        ];
        tableRows.push(rowData);
      }
    });

    doc.autoTable({
      head: [tableColumn],
      body: tableRows,
      startY: 35,
      // UPRAVENÉ: Pridané nastavenie písma pre tabuľku
      headStyles: { fillColor: [41, 128, 185], textColor: 255, font: doc.getFont().fontName },
      styles: { fontSize: 9, font: doc.getFont().fontName },
      alternateRowStyles: { fillColor: [240, 240, 240] },
      columnStyles: { 4: { cellWidth: 'auto' } }
    });

    const finalY = doc.lastAutoTable.finalY || 35;
    doc.setFontSize(10);
    const totalSalaryText = totalSalaryDiv.textContent || '';
    let daysWithEntriesText = 'N/A';
    const match = totalSalaryText.match(/Počet odpracovaných dní: (\d+)/);
    if (match && match[1]) {
      daysWithEntriesText = match[1];
    }
    const summaryText = `Počet odpracovaných dní: ${daysWithEntriesText}`;
    doc.text(summaryText, 14, finalY + 10);

    const pdfBlob = doc.output('blob');
    const pdfFileName = `Vykaz_odoslanie-${employeeName || 'pracovnik'}-${getMonthName(currentMonth)}-${currentYear}.pdf`;
    const pdfFile = new File([pdfBlob], pdfFileName, { type: 'application/pdf' });

    if (navigator.share && navigator.canShare && navigator.canShare({ files: [pdfFile] })) {
      navigator.share({
        files: [pdfFile],
        title: `Pracovný výkaz ${getMonthName(currentMonth)} ${currentYear}`,
        text: `Výkaz pre ${employeeName || 'pracovníka'} za ${getMonthName(currentMonth)} ${currentYear}.`
      }).then(() => {
        showSaveNotification("PDF pripravené na zdieľanie.");
      }).catch((error) => {
        if (error.name !== 'AbortError') {
          console.error('Chyba pri zdieľaní:', error);
          alert('Chyba pri zdieľaní súboru.');
        }
      });
    } else {
      alert("Zdieľanie súborov nie je podporované. Súbor bude stiahnutý.");
      const url = URL.createObjectURL(pdfBlob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = pdfFileName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }
  } catch (error) {
    console.error("Chyba pri generovaní alebo zdieľaní PDF:", error);
    alert("Nastala chyba pri vytváraní alebo zdieľaní PDF súboru.");
  }
}

function changeDecimalPlaces() {
  const newDecimalPlaces = parseInt(decimalPlacesSelect.value);
  if (!isNaN(newDecimalPlaces) && newDecimalPlaces >= 1 && newDecimalPlaces <= 2) {
    decimalPlaces = newDecimalPlaces;
    calculateTotal();
    saveToLocalStorage();
  }
}

function updateEmployeeName() {
  employeeName = employeeNameInput.value;
  updateWelcomeMessage();
  saveToLocalStorage();
}

function updateSettings() {
  let settingsChanged = false;

  // Validácia hodinovej mzdy
  const wageValidation = validateNumber(
    hourlyWageInput.value,
    0,
    VALIDATION_RULES.MAX_HOURLY_WAGE,
    'Hodinová mzda'
  );

  if (wageValidation.valid && wageValidation.value !== '') {
    const newHourlyWage = wageValidation.value;
    if (hourlyWage !== newHourlyWage) {
      hourlyWage = newHourlyWage;
      settingsChanged = true;
    }
    clearValidationError(hourlyWageInput);
  } else if (!wageValidation.valid) {
    showValidationError(hourlyWageInput, wageValidation.error);
  }

  // Validácia daňovej sadzby
  const taxValidation = validateNumber(
    taxRateInput.value,
    0,
    VALIDATION_RULES.MAX_TAX_RATE,
    'Daňová sadzba'
  );

  if (taxValidation.valid && taxValidation.value !== '') {
    const newTaxRatePercent = taxValidation.value;
    const newTaxRateDecimal = newTaxRatePercent / 100;
    if (taxRate !== newTaxRateDecimal) {
      taxRate = newTaxRateDecimal;
      settingsChanged = true;
    }
    clearValidationError(taxRateInput);
  } else if (!taxValidation.valid) {
    showValidationError(taxRateInput, taxValidation.error);
  }

  if (settingsChanged) {
    const rows = workDays.querySelectorAll('tr');
    rows.forEach((row, index) => calculateRow(index + 1));
    calculateTotal();
    saveToLocalStorage();
  }
}

function changeMonth() {
  const selectedMonth = parseInt(monthSelect.value);
  if (currentMonth !== selectedMonth) {
    currentMonth = selectedMonth;
    handleMonthYearChange();
  }
}

function changeYear() {
  const selectedYear = parseInt(yearSelect.value);
  if (currentYear !== selectedYear) {
    currentYear = selectedYear;
    handleMonthYearChange();
  }
}

function handleMonthYearChange() {
  localStorage.setItem('currentMonth', currentMonth.toString());
  localStorage.setItem('currentYear', currentYear.toString());
  loadFromLocalStorage();
  if (auth.currentUser) {
    setupFirestoreListener();
  }
}

function getDaysInMonth(month) {
  if (month === undefined || month === null || currentYear === undefined || currentYear === null) {
    return 31;
  }
  return new Date(currentYear, month + 1, 0).getDate();
}

function getMonthName(month) {
  const monthNames = ["Január", "Február", "Marec", "Apríl", "Máj", "Jún", "Júl", "August", "September", "Október", "November", "December"];
  return monthNames[month] || 'Neznámy';
}

function updateDataSize() {
  try {
    const totalData = Object.values(localStorage).reduce((acc, value) => acc + (value ? value.length : 0), 0);
    const kilobytes = (totalData / 1024).toFixed(2);
    const percentageUsed = Math.min(((totalData / MAX_DATA_SIZE) * 100), 100);
    
    dataSizeText.textContent = `Lokálne úložisko: ~${kilobytes} KB / ${MAX_DATA_SIZE_KB} KB`;
    dataSizeFill.style.width = `${percentageUsed}%`;

    if (percentageUsed > 90) {
      dataSizeFill.style.backgroundColor = '#f44336';
    } else if (percentageUsed > 70) {
      dataSizeFill.style.backgroundColor = '#ff9800';
    } else {
      dataSizeFill.style.backgroundColor = '#4CAF50';
    }
  } catch (error) {
    console.error("Chyba pri výpočte veľkosti localStorage:", error);
    dataSizeText.textContent = "Chyba pri výpočte veľkosti dát.";
  }
}

function toggleDarkMode() {
  const isDarkMode = document.body.classList.toggle('dark-mode');
  applyDarkMode(isDarkMode);
  localStorage.setItem('darkMode', JSON.stringify(isDarkMode));
  if (auth.currentUser) {
    saveToFirebase();
  }
}

function createBackup() {
  try {
    const backupData = {
      workDaysData: localStorage.getItem('workDaysData') || '{}',
      hourlyWage: localStorage.getItem('hourlyWage') || JSON.stringify(10),
      taxRate: localStorage.getItem('taxRate') || JSON.stringify(2),
      darkMode: localStorage.getItem('darkMode') || JSON.stringify(false),
      decimalPlaces: localStorage.getItem('decimalPlaces') || JSON.stringify(1),
      employeeName: localStorage.getItem('employeeName') || JSON.stringify(''),
      backupVersion: 2,
      backupTimestamp: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bruno-calculator-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showSaveNotification("Záloha úspešne vytvorená.");
  } catch (error) {
    console.error("Chyba pri vytváraní zálohy:", error);
    alert("Nastala chyba pri vytváraní záložného súboru.");
  }
}

function restoreBackup() {
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = '.json,application/json';
  
  fileInput.onchange = (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const backup = JSON.parse(e.target.result);
        if (backup && typeof backup.workDaysData === 'string' && typeof backup.hourlyWage === 'string' && typeof backup.taxRate === 'string' && typeof backup.darkMode === 'string' && typeof backup.decimalPlaces === 'string' && typeof backup.employeeName === 'string') {
          localStorage.setItem('workDaysData', backup.workDaysData);
          localStorage.setItem('hourlyWage', backup.hourlyWage);
          localStorage.setItem('taxRate', backup.taxRate);
          localStorage.setItem('darkMode', backup.darkMode);
          localStorage.setItem('decimalPlaces', backup.decimalPlaces);
          localStorage.setItem('employeeName', backup.employeeName);
          
          loadFromLocalStorage();
          showSaveNotification("Záloha úspešne obnovená.");
          alert("Záloha bola úspešne obnovená. Dáta boli načítané.");
          
          if (auth.currentUser) {
            saveToLocalStorage();
          }
        } else {
          alert("Chyba: Súbor zálohy má nesprávny formát alebo chýbajú dáta.");
        }
      } catch (error) {
        console.error("Chyba pri spracovaní alebo obnove zálohy:", error);
        alert("Chyba pri čítaní alebo obnove zálohy. Súbor môže byť poškodený alebo mať nesprávny formát.");
      }
    };
    
    reader.onerror = (e) => {
      console.error("Chyba pri čítaní súboru zálohy:", e);
      alert("Nastala chyba pri čítaní súboru zálohy.");
    };
    
    reader.readAsText(file);
  };
  
  fileInput.click();
}

document.addEventListener('DOMContentLoaded', () => {
  populateYearSelect();
  const darkMode = JSON.parse(localStorage.getItem('darkMode')) || false;
  applyDarkMode(darkMode);
  updateWelcomeMessage();

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./service-worker.js')
        .then(registration => {})
        .catch(error => {
          console.error('Registrácia ServiceWorker zlyhala: ', error);
        });
    });
  }
});

function populateYearSelect() {
  const startYear = 2020;
  const endYear = new Date().getFullYear() + 2;
  yearSelect.replaceChildren();

  for (let year = startYear; year <= endYear; year++) {
    const option = document.createElement('option');
    option.value = year;
    option.textContent = year;
    yearSelect.appendChild(option);
  }
}

// ========================================
// EVENT LISTENERS - Nahradenie inline handlers
// ========================================

// Wait for DOM to be fully loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initEventListeners);
} else {
  initEventListeners();
}

function initEventListeners() {
  // Guard: zabráň viacnásobnej inicializácii event listenerov
  if (eventListenersAttached) {
    return;
  }

  // Validácia kritických elementov pred pripojením listenerov
  if (!workDays) {
    console.error('[Event Listeners] CHYBA: workDays element neexistuje! Event delegation nemôže byť inicializovaná.');
    // Guard NENASTAVUJEME - umožníme ďalší pokus po načítaní DOM
    return;
  }

  // Auth buttons
  const registerBtn = document.getElementById('registerBtn');
  const loginBtn = document.getElementById('loginBtn');
  const forgotPasswordLink = document.getElementById('forgot-password-link');
  const logoutBtn = document.getElementById('logout-btn');

  if (registerBtn) registerBtn.addEventListener('click', register);
  if (loginBtn) loginBtn.addEventListener('click', login);
  if (forgotPasswordLink) forgotPasswordLink.addEventListener('click', forgotPassword);
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  // Settings inputs
  const monthSelectEl = document.getElementById('monthSelect');
  const yearSelectEl = document.getElementById('yearSelect');
  const decimalPlacesSelectEl = document.getElementById('decimalPlacesSelect');
  const employeeNameInputEl = document.getElementById('employeeNameInput');
  const hourlyWageInputEl = document.getElementById('hourlyWageInput');
  const taxRateInputEl = document.getElementById('taxRateInput');

  if (monthSelectEl) monthSelectEl.addEventListener('change', changeMonth);
  if (yearSelectEl) yearSelectEl.addEventListener('change', changeYear);
  if (decimalPlacesSelectEl) decimalPlacesSelectEl.addEventListener('change', changeDecimalPlaces);
  if (employeeNameInputEl) employeeNameInputEl.addEventListener('input', updateEmployeeName);
  if (hourlyWageInputEl) hourlyWageInputEl.addEventListener('input', updateSettings);
  if (taxRateInputEl) taxRateInputEl.addEventListener('input', updateSettings);

  // Action buttons
  const toggleDarkModeBtn = document.getElementById('toggleDarkModeBtn');
  const resetAllBtn = document.getElementById('resetAllBtn');
  const exportPDFBtn = document.getElementById('exportPDFBtn');
  const sendPDFBtn = document.getElementById('sendPDFBtn');
  const restoreBackupBtn = document.getElementById('restoreBackupBtn');
  const createBackupBtn = document.getElementById('createBackupBtn');

  if (toggleDarkModeBtn) toggleDarkModeBtn.addEventListener('click', toggleDarkMode);
  if (resetAllBtn) resetAllBtn.addEventListener('click', resetAll);
  if (exportPDFBtn) exportPDFBtn.addEventListener('click', exportToPDF);
  if (sendPDFBtn) sendPDFBtn.addEventListener('click', sendPDF);
  if (restoreBackupBtn) restoreBackupBtn.addEventListener('click', restoreBackup);
  if (createBackupBtn) createBackupBtn.addEventListener('click', createBackup);

  // Event delegation na workDays pre dynamické elementy
  if (workDays) {
    // Input events (start, end, breakTime, note)
    workDays.addEventListener('input', (e) => {
      const target = e.target;
      const day = parseInt(target.dataset.day);
      const field = target.dataset.field;

      if (!day || !field) return;

      if (field === 'start' || field === 'end') {
        const nextFieldId = target.dataset.nextField;
        handleInput(target, nextFieldId, day);
      } else if (field === 'breakTime') {
        handleBreakInput(day);
      } else if (field === 'note') {
        handleNoteInput(target, day);
      }
    });

    // Click events (insert-time, toggle-note, reset-row)
    workDays.addEventListener('click', (e) => {
      const target = e.target.closest('[data-action]');
      if (!target) return;

      const action = target.dataset.action;

      if (action === 'insert-time') {
        const targetInputId = target.dataset.target;
        insertCurrentTime(targetInputId);
      } else if (action === 'toggle-note') {
        const day = parseInt(target.dataset.day);
        if (day) toggleNote(day);
      } else if (action === 'reset-row') {
        const day = parseInt(target.dataset.day);
        if (day) resetRow(day);
      }
    });
  }

  // Guard nastavený až PO úspešnom pripojení všetkých listenerov
  eventListenersAttached = true;
}

// Funkcie insertCurrentTime, toggleNote, resetRow, handleInput, handleBreakInput, handleNoteInput
// sú teraz volané cez event delegation, takže už nie sú potrebné ako window.* exports

// ========================================
// ŠTART APLIKÁCIE
// ========================================
initApp();
