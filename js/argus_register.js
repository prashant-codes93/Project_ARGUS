 const eyeOpen = '<path d="M1 12s4-7.5 11-7.5S23 12 23 12s-4 7.5-11 7.5S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>';
  const eyeClosed = '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 19.5C5 19.5 1 12 1 12a21.4 21.4 0 0 1 5.06-6.06M9.9 4.24A10.94 10.94 0 0 1 12 4.5c7 0 11 7.5 11 7.5a21.4 21.4 0 0 1-2.66 3.79M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

  document.querySelectorAll('.toggle-visibility').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const field = document.getElementById(targetId);
      const icon = btn.querySelector('.eyeIcon');
      const isPassword = field.type === 'password';
      field.type = isPassword ? 'text' : 'password';
      icon.innerHTML = isPassword ? eyeClosed : eyeOpen;
      btn.setAttribute('aria-pressed', String(isPassword));
      btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
  });

  // ---------- password strength ----------
  const pwField = document.getElementById('password');
  const bars = document.querySelectorAll('#strengthBars i');
  const strengthLabel = document.getElementById('strengthLabel');
  const barColors = ['#c94848', '#c98a3a', '#c9a63a', '#1f9d6b'];
  const barLabels = ['Weak', 'Fair', 'Good', 'Strong'];

  function scorePassword(pw){
    let score = 0;
    if (pw.length >= 8) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return score;
  }

  pwField.addEventListener('input', () => {
    const pw = pwField.value;
    const score = pw.length === 0 ? 0 : Math.max(1, scorePassword(pw));
    bars.forEach((bar, i) => {
      bar.style.background = i < score ? barColors[score-1] : 'var(--panel-line)';
    });
    strengthLabel.textContent = pw.length === 0
      ? 'Use 8+ characters with a number and a symbol.'
      : barLabels[score-1] + ' password';
    strengthLabel.style.color = pw.length === 0 ? 'var(--muted-2)' : barColors[score-1];
    clearFieldError('password');
  });

  // ---------- field error helpers ----------
  function setFieldError(fieldKey, message){
    const wrap = document.getElementById(fieldKey + 'Wrap');
    const err = document.getElementById(fieldKey + 'Error');
    if (wrap) wrap.classList.add('field-error');
    if (err){
      if (message) err.textContent = message;
      err.classList.add('show');
    }
  }
  function clearFieldError(fieldKey){
    const wrap = document.getElementById(fieldKey + 'Wrap');
    const err = document.getElementById(fieldKey + 'Error');
    if (wrap) wrap.classList.remove('field-error');
    if (err) err.classList.remove('show');
  }
  ['fullName','username','password','confirmPassword'].forEach(key => {
    const el = document.getElementById(key);
    if (el) el.addEventListener('input', () => clearFieldError(key));
  });
  document.getElementById('terms').addEventListener('change', () => {
    document.getElementById('termsError').classList.remove('show');
  });

  // ---------- simulated "already taken" data ----------
  const takenUsernames = ['admin', 'rohan.kumar'];
  const takenEmails = ['admin@argus.io', 'test@argus.io'];

  // ---------- OTP flow ----------
  const emailField = document.getElementById('email');
  const emailWrap = document.getElementById('emailWrap');
  const sendOtpBtn = document.getElementById('sendOtpBtn');
  const verifiedBadge = document.getElementById('verifiedBadge');
  const otpBlock = document.getElementById('otpBlock');
  const otpNote = document.getElementById('otpNote');
  const otpInputs = [...document.querySelectorAll('#otpInputs input')];
  const verifyOtpBtn = document.getElementById('verifyOtpBtn');
  const otpError = document.getElementById('otpError');
  const otpTimerEl = document.getElementById('otpTimer');
  const resendOtpBtn = document.getElementById('resendOtpBtn');

  let currentOtp = null;
  let emailVerified = false;
  let expiryInterval = null;
  let resendInterval = null;

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  function generateOtp(){
    return String(Math.floor(100000 + Math.random() * 900000));
  }

  function startExpiryCountdown(){
    let secondsLeft = 300;
    clearInterval(expiryInterval);
    expiryInterval = setInterval(() => {
      secondsLeft--;
      const m = String(Math.floor(secondsLeft / 60)).padStart(2, '0');
      const s = String(secondsLeft % 60).padStart(2, '0');
      otpTimerEl.textContent = `Code expires in ${m}:${s}`;
      if (secondsLeft <= 0){
        clearInterval(expiryInterval);
        otpTimerEl.textContent = 'Code expired — request a new one';
        currentOtp = null;
      }
    }, 1000);
  }

  function startResendCooldown(){
    let secondsLeft = 60;
    resendOtpBtn.disabled = true;
    resendOtpBtn.textContent = `Resend code (${secondsLeft}s)`;
    clearInterval(resendInterval);
    resendInterval = setInterval(() => {
      secondsLeft--;
      if (secondsLeft <= 0){
        clearInterval(resendInterval);
        resendOtpBtn.disabled = false;
        resendOtpBtn.textContent = 'Resend code';
      } else {
        resendOtpBtn.textContent = `Resend code (${secondsLeft}s)`;
      }
    }, 1000);
  }

  function sendOtp(){
    const email = emailField.value.trim();
    if (!email){
      setFieldError('email', 'Enter your email first.');
      return;
    }
    if (!emailPattern.test(email)){
      setFieldError('email', 'Enter a valid email address.');
      return;
    }
    if (takenEmails.includes(email.toLowerCase())){
      setFieldError('email', 'An account with this email already exists.');
      return;
    }
    clearFieldError('email');

    currentOtp = generateOtp();
    otpBlock.classList.add('show');
    otpError.classList.remove('show');
    otpInputs.forEach(i => i.value = '');
    otpInputs[0].focus();
    startExpiryCountdown();
    startResendCooldown();

    otpNote.innerHTML = `Preview mode — no real email is sent from this page. In production this code goes to <strong>${email}</strong> via your backend's email service. Demo code: <strong>${currentOtp}</strong>`;
  }

  sendOtpBtn.addEventListener('click', sendOtp);
  resendOtpBtn.addEventListener('click', () => { if (!resendOtpBtn.disabled) sendOtp(); });

  otpInputs.forEach((input, idx) => {
    input.addEventListener('input', () => {
      input.value = input.value.replace(/[^0-9]/g, '').slice(0,1);
      if (input.value && idx < otpInputs.length - 1) otpInputs[idx+1].focus();
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !input.value && idx > 0) otpInputs[idx-1].focus();
    });
    input.addEventListener('paste', (e) => {
      const text = (e.clipboardData.getData('text') || '').replace(/[^0-9]/g,'').slice(0,6);
      if (text.length){
        e.preventDefault();
        text.split('').forEach((ch, i) => { if (otpInputs[i]) otpInputs[i].value = ch; });
        otpInputs[Math.min(text.length, otpInputs.length) - 1].focus();
      }
    });
  });

  verifyOtpBtn.addEventListener('click', () => {
    const entered = otpInputs.map(i => i.value).join('');
    if (entered.length < 6){
      otpError.textContent = 'Enter all 6 digits.';
      otpError.classList.add('show');
      return;
    }
    if (!currentOtp || entered !== currentOtp){
      otpError.textContent = "That code isn't right. Check your inbox and try again.";
      otpError.classList.add('show');
      return;
    }
    otpError.classList.remove('show');
    emailVerified = true;
    clearInterval(expiryInterval);
    clearInterval(resendInterval);
    otpBlock.classList.remove('show');
    emailField.disabled = true;
    emailWrap.classList.add('field-verified');
    sendOtpBtn.style.display = 'none';
    verifiedBadge.style.display = 'inline-flex';
  });

  emailField.addEventListener('input', () => {
    clearFieldError('email');
    if (emailVerified){
      emailVerified = false;
      emailField.disabled = false;
      emailWrap.classList.remove('field-verified');
      verifiedBadge.style.display = 'none';
      sendOtpBtn.style.display = 'inline-block';
    }
  });

  // ---------- submit ----------
  const form = document.getElementById('registerForm');
  const formMsg = document.getElementById('formMsg');
  const submitBtn = document.getElementById('submitBtn');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    formMsg.classList.remove('show', 'success');

    const fullName = document.getElementById('fullName').value.trim();
    const username = document.getElementById('username').value.trim();
    const email = emailField.value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const terms = document.getElementById('terms').checked;

    let firstErrorField = null;
    let hasError = false;

    if (!fullName){
      setFieldError('fullName', 'Full name is required.');
      hasError = true; firstErrorField = firstErrorField || 'fullName';
    }
    if (!username){
      setFieldError('username', 'Username is required.');
      hasError = true; firstErrorField = firstErrorField || 'username';
    } else if (takenUsernames.includes(username.toLowerCase())){
      setFieldError('username', 'This username is already taken.');
      hasError = true; firstErrorField = firstErrorField || 'username';
    }

    if (!email){
      setFieldError('email', 'Email is required.');
      hasError = true; firstErrorField = firstErrorField || 'email';
    } else if (!emailPattern.test(email)){
      setFieldError('email', 'Enter a valid email address.');
      hasError = true; firstErrorField = firstErrorField || 'email';
    } else if (!emailVerified){
      setFieldError('email', 'Verify your email with the OTP before continuing.');
      hasError = true; firstErrorField = firstErrorField || 'email';
    }

    if (!password){
      setFieldError('password', 'Password is required.');
      hasError = true; firstErrorField = firstErrorField || 'password';
    } else if (scorePassword(password) < 3){
      setFieldError('password', 'Password is too weak — add a number, a symbol, and mix upper/lowercase.');
      hasError = true; firstErrorField = firstErrorField || 'password';
    }

    if (!confirmPassword){
      setFieldError('confirmPassword', 'Confirm your password.');
      hasError = true; firstErrorField = firstErrorField || 'confirmPassword';
    } else if (password && confirmPassword !== password){
      setFieldError('confirmPassword', "Passwords don't match.");
      hasError = true; firstErrorField = firstErrorField || 'confirmPassword';
    }

    if (!terms){
      document.getElementById('termsError').classList.add('show');
      hasError = true; firstErrorField = firstErrorField || 'terms';
    }

    if (hasError){
      formMsg.textContent = 'Fix the highlighted fields and try again.';
      formMsg.classList.add('show');
      const el = document.getElementById(firstErrorField);
      if (el) el.focus();
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = 'Creating account…';

    setTimeout(() => {
      document.getElementById('formView').style.display = 'none';
      document.getElementById('successView').style.display = 'block';
      document.getElementById('successText').textContent =
        `Your admin profile for ${fullName.split(' ')[0]} is ready. Sign in to open your dashboard.`;
    }, 900);
  });

  document.getElementById('termsLink').addEventListener('click', (e) => {
    e.preventDefault();
    alert('Wire this up to your Terms & Conditions page.');
  });