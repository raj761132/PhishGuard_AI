// Function to go to Next Step
function nextStep(currentStep) {
    // Simple Validation (Optional: Add more strict checks here)
    if (currentStep === 1) {
        const name = document.getElementById('orgName').value;
        if (!name) { alert("Please enter Organization Name"); return; }
    }
    if (currentStep === 2) {
        const email = document.getElementById('officialEmail').value;
        if (!email.includes('@')) { alert("Please enter a valid official email"); return; }
    }

    // Hide Current
    document.getElementById('section' + currentStep).classList.remove('active');
    // Show Next
    document.getElementById('section' + (currentStep + 1)).classList.add('active');
    
    // Update Indicators
    const currIndicator = document.getElementById('step' + currentStep);
    currIndicator.classList.remove('active');
    currIndicator.classList.add('completed');
    currIndicator.style.background = "#198754"; // Green
    currIndicator.style.borderColor = "#198754";
    currIndicator.style.color = "#fff";
    currIndicator.innerHTML = '<i class="fas fa-check"></i>';

    const nextIndicator = document.getElementById('step' + (currentStep + 1));
    nextIndicator.classList.add('active');
}

// Function to go Back
function prevStep(currentStep) {
    document.getElementById('section' + currentStep).classList.remove('active');
    document.getElementById('section' + (currentStep - 1)).classList.add('active');
    
    // Reset Indicators
    const prevIndicator = document.getElementById('step' + (currentStep - 1));
    prevIndicator.classList.remove('completed');
    prevIndicator.classList.add('active');
    prevIndicator.innerHTML = (currentStep - 1);
    prevIndicator.style.background = "#0d6efd"; // Back to Blue
    
    document.getElementById('step' + currentStep).classList.remove('active');
}

// Final Submit
function handleSubmit(e) {
    e.preventDefault();
    alert("Application Submitted Successfully! \n\nReference ID: ORG-APP-2024-899\n\nPlease check your email for approval status within 24-48 hours.");
    window.location.href = "auth.html";
}