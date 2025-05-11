# 🔐 Secure Social Media & Marketplace

This project is a full-stack **secure social media platform with marketplace integration**, developed as part of the *Foundations of Computer Security* course at IIIT-Delhi. It supports real-time messaging, media sharing, and P2P product listings — all backed by strong security practices and live attack defense.

---

## 🚀 Features Overview

### 🔐 Security-First Design
- HTTPS-secured deployment (TLS 1.2/1.3)
- OTP-based email verification with virtual keyboard
- End-to-end encrypted messaging
- Public Key Infrastructure (PKI) for secure workflows
- Secure audit logging and access control

### 👥 Social Platform
- User registration, login, and profile management
- Friend request, block, and search functionality
- Real-time one-to-one and group chat support

### 🛒 Marketplace
- Verified users can list and browse products
- Add to cart and place orders
- Admin-monitored content and transaction access

### 🛡️ Admin Panel
- View, verify, suspend, or remove accounts
- Process reports and flagged content
- Access system logs for moderation and auditing

---

## 🧠 Application Architecture

| Module       | Purpose |
|--------------|---------|
| `Users`      | Handles authentication, sessions, profile management, middleware |
| `Marketplace`| Handles listings, orders, and search |
| `Admin`      | Moderation dashboard and privileged actions |
| `Security`   | OTP logic, PKI verification, logging, and route protection |

The platform uses a modular Django architecture and was deployed on a VM using **Nginx + Gunicorn**, with static/media routing and rate-limiting protections.

---

## 📲 How to Use

1. **Sign Up**  
   Register using email → Verify with OTP.

2. **Find Friends**  
   Use search → Send and accept friend requests.

3. **Start Messaging**  
   Access one-to-one messaging once connected.  
   Use your private key when prompted (keep it safe).

4. **Group Messaging & Marketplace**  
   Requires admin verification. Email `nikhil22322@iiitd.ac.in` to get verified.

5. **Manage Profile**  
   Change password, update profile picture and bio, view blocked users.

6. **Marketplace**  
   Browse or create product listings, add items to cart, and place orders.

---

---

## 🔐 Security Features Implemented

| Feature               | Description |
|-----------------------|-------------|
| OTP Verification      | Secured with virtual keyboard against keylogging |
| PKI                   | Used for OTP signing and user verification |
| Session Protection    | Middleware-secured access; session cookie security enforced |
| Secure Deployment     | TLS, HSTS, security headers via Nginx |
| Admin Moderation      | Live handling of abuse reports and account bans |
| Secure Logging        | Tamper-resistant logs for audits and moderation |

---

## 🌐 Deployment Overview

- **OS**: Ubuntu (VM)
- **Web Server**: Nginx (with HTTPS, rate limiting, and headers)
- **App Server**: Gunicorn with systemd service
- **Database**: MySQL
- **Framework**: Django

> Nginx served static/media files and reverse-proxied requests to Gunicorn. TLS certificates were generated and deployed for secure HTTPS access.

---

## 👨‍💻 Team — *THE404s*

- **Nikhil Kumar** – OTP system, deployment, session security, admin verification
- **Aditya Kumar Sinha** – Messaging system, audit logging, profile management
- **Dhruv** – Marketplace module, search, friend system
- **Pandillapelly Harshvardhini** – Admin dashboard, stored XSS defense, middleware

---

## 📬 Support

For any technical support, reach out to:

📧 **nikhil22322@iiitd.ac.in**

---

## 🔚 Final Notes

This project demonstrates a practical and secure social platform — deployed on a live server and hardened against attacks in a testbed environment. It integrates **security by design** into all its features — from OTP login to encrypted communication and admin-level moderation.
