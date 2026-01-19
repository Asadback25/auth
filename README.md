# Django Users Authentication System

This is a **Django + DRF** authentication system with **JWT**, **OTP verification**, and **Swagger documentation**.  

It includes:

- User Registration with OTP verification
- Login with JWT token
- Logout with token blacklist
- Forgot Password + Reset Password with OTP
- Swagger/OpenAPI interactive documentation
- Console email backend for testing OTP codes

---

## ⚡ Features

1. **Register**  
   - Users register with username, email, and password  
   - OTP is generated and sent to email (console backend for testing)  
   - User must verify OTP to activate account  

2. **Login**  
   - Authenticated via username/email + password  
   - Returns **Access + Refresh JWT tokens**  

3. **Logout**  
   - Invalidates (blacklists) refresh token  
   - Protected endpoint, requires **access token** in header  

4. **Forgot Password**  
   - Users enter email  
   - OTP sent to email (console)  

5. **Reset Password**  
   - Users provide username, OTP, and new password  
   - Password is updated if OTP is valid  

6. **Swagger / Redoc Documentation**  
   - Interactive API documentation  
   - Test endpoints directly from UI  

---


