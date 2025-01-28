document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const successMessage = document.getElementById('successMessage');
    
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault(); // Prevent form from submitting the traditional way

        const email = emailInput.value;
        const password = passwordInput.value;

        try {
            const response = await fetch('http://localhost:3000/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const result = await response.json();

            if (response.ok) {
                // Show success message and do something after login
                successMessage.style.display = 'block';
                setTimeout(() => {
                    successMessage.style.display = 'none';
                    // Redirect or perform other actions if needed
                    // window.location.href = '/dashboard'; // Example redirect
                }, 3000);
            } else {
                // Show error message from the backend
                alert(`Error: ${result.error || 'Login failed. Please try again.'}`);
            }
        } catch (error) {
            // Handle unexpected errors (e.g., network issues)
            alert('Error: An unexpected error occurred');
        }
    });
});
