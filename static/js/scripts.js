document.getElementById('login-btn').addEventListener('click', () => {
    window.location.href = '/login';
});

document.addEventListener('DOMContentLoaded', async () => {
    // Do NOT trigger any authentication automatically on page load
    // User must click buttons to authenticate
});

document.getElementById('kerberos-auth-btn').addEventListener('click', async () => {
    const response = await fetch('/kerberos-auth', { method: 'POST' });
    const data = await response.json();
    const kerberosStatus = document.querySelector('#user-info p:nth-child(2)');
    const kerberosUser = document.querySelector('#user-info p:nth-child(3)');
    const resourceData = document.getElementById('resource-data');

    if (response.ok) {
        kerberosStatus.innerText = "Kerberos Authenticated: Yes";
        kerberosUser.innerText = `Kerberos User: ${data.message.split(': ')[1]}`;
        resourceData.innerText = JSON.stringify(data.resource_data, null, 2); // Display resource data
    } else {
        kerberosStatus.innerText = "Kerberos Authenticated: No";
        kerberosUser.innerText = "Kerberos User: N/A";
        alert(data.message || "Kerberos Authentication Failed!");
    }
});

document.getElementById('access-resource-btn').addEventListener('click', async () => {
    const response = await fetch('/access-resource', { method: 'POST' });
    const data = await response.json();
    if (response.ok) {
        console.log(data);
        alert('Accessed resource successfully. Check console for details.');
    } else {
        alert(data.message);
    }
});