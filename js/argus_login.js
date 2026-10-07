const toggleBtn = document.getElementById('toggleVisibility');
const pwField = document.getElementById('password');
const eyeIcon = document.getElementById('eyeIcon');

const eyeOpen =
  '<path d="M1 12s4-7.5 11-7.5S23 12 23 12s-4 7.5-11 7.5S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>';

const eyeClosed =
  '<path d="M17.94 17.94A10.94 10.94 0 0 1 12 19.5C5 19.5 1 12 1 12a21.4 21.4 0 0 1 5.06-6.06M9.9 4.24A10.94 10.94 0 0 1 12 4.5c7 0 11 7.5 11 7.5a21.4 21.4 0 0 1-2.66 3.79M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';


// =========================================================
// PASSWORD VISIBILITY
// =========================================================

toggleBtn.addEventListener('click', () => {

  const isPassword = pwField.type === 'password';

  pwField.type = isPassword ? 'text' : 'password';

  eyeIcon.innerHTML = isPassword
    ? eyeClosed
    : eyeOpen;

  toggleBtn.setAttribute(
    'aria-pressed',
    String(isPassword)
  );

  toggleBtn.setAttribute(
    'aria-label',
    isPassword
      ? 'Hide password'
      : 'Show password'
  );
});


// =========================================================
// LOGIN
// =========================================================

const form = document.getElementById('loginForm');
const msg = document.getElementById('formMsg');

form.addEventListener('submit', async (e) => {

  e.preventDefault();

  const username =
    document.getElementById('identifier').value.trim();

  const password = pwField.value;

  // -------------------------------------------------------
  // Validate
  // -------------------------------------------------------

  if (!username || !password) {

    msg.textContent =
      'Enter both username and password.';

    msg.classList.add('show');

    return;
  }

  const btn = form.querySelector('.submit');

  const original = btn.innerHTML;

  btn.innerHTML = 'Signing in…';

  btn.disabled = true;

  msg.classList.remove('show');


  try {

    // -----------------------------------------------------
    // Send login request
    // -----------------------------------------------------

    const response = await fetch(
      'http://127.0.0.1:5000/api/auth/login',
      {
        method: 'POST',

        headers: {
          'Content-Type': 'application/json'
        },

        body: JSON.stringify({
          username: username,
          password: password
        })
      }
    );


    const data = await response.json();


    // -----------------------------------------------------
    // Check login response
    // -----------------------------------------------------

    if (!response.ok) {

      throw new Error(
        data.error || 'Login failed'
      );
    }


    // =====================================================
    // IMPORTANT:
    // CLEAR PREVIOUS USER'S SCAN SESSION DATA
    // =====================================================

    sessionStorage.removeItem(
      'argus_current_scan_id'
    );

    sessionStorage.removeItem(
      'argus_current_scan_count'
    );

    sessionStorage.removeItem(
      'argus_last_uploaded_file'
    );


    // =====================================================
    // SAVE NEW USER'S JWT
    // =====================================================

    localStorage.setItem(
      'argus_token',
      data.token
    );


    // Backend returns role inside data.user
    localStorage.setItem(
      'argus_role',
      data.user?.role || 'analyst'
    );


    // Optional: save the current username
    localStorage.setItem(
      'argus_username',
      data.user?.username || username
    );


    console.log(
      'ARGUS LOGIN SUCCESS'
    );

    console.log(
      'Username:',
      data.user?.username || username
    );

    console.log(
      'User ID:',
      data.user?.id
    );

    console.log(
      'Token saved:',
      !!localStorage.getItem('argus_token')
    );

    console.log(
      'Previous scan data cleared'
    );


    // -----------------------------------------------------
    // Open dashboard
    // -----------------------------------------------------

    window.location.href =
      'argus_dashboard.html';


  } catch (error) {

    console.error(
      'Login error:',
      error
    );

    msg.textContent =
      error.message;

    msg.classList.add('show');

    btn.innerHTML = original;

    btn.disabled = false;
  }

});