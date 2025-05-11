# 🔐 Secure Social Media Marketplace

This is a full-stack **social media platform with marketplace features** developed as part of the **Foundations of Computer Security** course at IIIT-Delhi. The application was built to simulate a real-world environment with strong security guarantees across user interactions, messaging, and media sharing.

It was deployed on a secure Ubuntu-based virtual machine, and tested against various common attack vectors as part of the final defense.

---

## 🚀 Features Overview

### 🔐 Security-First Design
- HTTPS-secured deployment (TLS 1.2/1.3)
- OTP-based user verification with virtual keyboard
- End-to-end encryption for messages
- Secure media upload/download
- Public Key Infrastructure (PKI) integration
- Tamper-resistant logging and audit trails

### 👥 Social Media Core
- User registration with OTP and email verification
- Friend requests and blocking
- Real-time 1:1 and group messaging
- Profile management (bio, image, password)

### 🛒 Marketplace
- List and browse products
- Add items to cart and place orders
- Admin-verified access for transactions

### 🛡️ Admin Features
- View, verify, suspend or remove users
- Handle reported content
- Access secure logs and violation reports

---

## 🧠 Architecture & Modules

| Module       | Description |
|--------------|-------------|
| **Users**    | Handles authentication, profile management, session control, and security middleware |
| **Marketplace** | Manages product listings, orders, and e-commerce views |
| **Admin**    | Restricted dashboard for user moderation and security oversight |
| **Security** | OTP service, PKI usage, rate-limiting, session protection, middleware enforcement |

> All core functionalities were implemented in a modular Django structure.

---
