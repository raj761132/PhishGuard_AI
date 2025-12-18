/* static/js/register.js */

// 1. Password Strength Logic
function checkStrength() {
    const pass = document.getElementById('regPass').value;
    const bar = document.getElementById('meterFill');
    let strength = 0;

    // Logic to increase bar width
    if (pass.length > 5) strength += 30;
    if (pass.match(/[0-9]/)) strength += 30;
    if (pass.match(/[!@#$%^&*]/)) strength += 40;

    bar.style.width = strength + "%";
    
    // Color Logic
    if (strength < 50) bar.style.backgroundColor = "#dc3545"; // Red
    else if (strength < 80) bar.style.backgroundColor = "#ffc107"; // Orange
    else bar.style.backgroundColor = "#198754"; // Green
}

// 2. Handle Form Submit
function handleRegistration(e) {
    e.preventDefault();
    
    const p1 = document.getElementById('regPass').value;
    const p2 = document.getElementById('regConfirm').value;

    // Validation
    if (p1 !== p2) {
        alert("Error: Passwords do not match!");
        return;
    }

    // Success Simulation
    alert("Registration Successful! Redirecting to Login...");
    window.location.href = "auth.html";
}