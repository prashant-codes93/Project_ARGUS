 const toggleBtn = document.getElementById('toggleVisibility');
  const pwField = document.getElementById('password');
  const eyeIcon = document.getElementById('eyeIcon');

  const eyeOpen = '<path d="M1 12s4-7.5 11-7.5S23 12 23 12s-4 7.5-11 7.5S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>';
  const eyeClosed = '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 19.5C5 19.5 1 12 1 12a21.4 21.4 0 0 1 5.06-6.06M9.9 4.24A10.94 10.94 0 0 1 12 4.5c7 0 11 7.5 11 7.5a21.4 21.4 0 0 1-2.66 3.79M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

  toggleBtn.addEventListener('click', () => {
    const isPassword = pwField.type === 'password';
    pwField.type = isPassword ? 'text' : 'password';
    eyeIcon.innerHTML = isPassword ? eyeClosed : eyeOpen;
    toggleBtn.setAttribute('aria-pressed', String(isPassword));
    toggleBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  });

  const form = document.getElementById('loginForm');
  const msg = document.getElementById('formMsg');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const identifier = document.getElementById('identifier').value.trim();
    const password = pwField.value;

    if (!identifier || !password) {
      msg.textContent = 'Enter both your username/email and password to continue.';
      msg.classList.add('show');
      return;
    }
    if (password.length < 6) {
      msg.textContent = 'That password looks too short — check for typos and try again.';
      msg.classList.add('show');
      return;
    }

    msg.classList.remove('show');
    const btn = form.querySelector('.submit');
    const original = btn.innerHTML;
    btn.innerHTML = 'Verifying…';
    btn.disabled = true;
  try {
    const response = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: identifier,
      password: password
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || 'Login failed');
  }

  msg.style.borderColor = '#2e5cb8';
  msg.style.color = '#1f4a9e';
  msg.style.background = 'rgba(46,92,184,0.07)';
  msg.textContent = 'Login successful! Welcome to Argus.';
msg.classList.add('show');

console.log('Logged in user:', data.user);

setTimeout(() => {
  window.location.href = 'argus_dashboard.html';
}, 800);

} 
catch (error) {
  msg.style.borderColor = '#c62828';
  msg.style.color = '#c62828';
  msg.style.background = 'rgba(198,40,40,0.07)';
  msg.textContent = error.message;
  msg.classList.add('show');

} finally {
  btn.innerHTML = original;
  btn.disabled = false;
}
  });

  document.getElementById('forgotLink').addEventListener('click', (e) => {
    e.preventDefault();
    alert('Wire this up to your password-reset flow.');
  });