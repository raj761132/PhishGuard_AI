document.addEventListener("DOMContentLoaded", function() {
    // 1. Get User Role from Storage (Saved during Login)
    const role = localStorage.getItem('currentUserRole');

    // If no role found (e.g. direct access), redirect to login
    if (!role) {
        window.location.href = "auth.html";
        return;
    }

    // 2. Setup Variables
    const body = document.getElementById('body-theme');
    const title = document.getElementById('sidebarTitle');
    const idDisplay = document.getElementById('sidebarId');
    const welcome = document.getElementById('welcomeMsg');
    const badge = document.getElementById('roleBadge');

    // 3. Logic Switch
    if (role === 'citizen') {
        // Apply Blue Theme
        body.classList.add('theme-citizen');
        title.innerText = "Citizen Portal";
        idDisplay.innerText = "ID: IND-8822";
        welcome.innerText = "Welcome, Citizen";
        badge.className = "badge bg-primary";
        badge.innerText = "Citizen";

        // Show Content
        document.getElementById('menu-citizen').classList.remove('d-none');
        document.getElementById('view-citizen').classList.remove('d-none');
    }
    else if (role === 'org') {
        // Apply Gold/Dark Theme
        body.classList.add('theme-org');
        title.innerText = "Org Admin";
        idDisplay.innerText = "ID: SBI-DEL-01";
        welcome.innerText = "Welcome, State Bank of India";
        badge.className = "badge bg-warning text-dark";
        badge.innerText = "Verified Org";

        // Show Content
        document.getElementById('menu-org').classList.remove('d-none');
        document.getElementById('view-org').classList.remove('d-none');
    }
    else if (role === 'admin') {
        // Apply Red Theme
        body.classList.add('theme-admin');
        title.innerText = "CERT-IN";
        idDisplay.innerText = "LEVEL: COMMANDER";
        welcome.innerText = "Central Command Center";
        badge.className = "badge bg-danger";
        badge.innerText = "Top Secret";

        // Show Content
        document.getElementById('menu-admin').classList.remove('d-none');
        document.getElementById('view-admin').classList.remove('d-none');
    }
});

// Logout Function
function doLogout() {
    localStorage.removeItem('currentUserRole');
    window.location.href = "auth.html";
}