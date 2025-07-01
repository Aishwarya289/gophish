# Phishing Simulation Project Using Gophish

##  Overview

This project demonstrates how to deploy and use [Gophish](https://getgophish.com), an open-source phishing simulation framework, to test user awareness against phishing attacks. The deployment was hosted on [Railway](https://railway.app), enabling a cloud-accessible admin portal and phishing server.

##  Tools & Technologies

* **Gophish** - Open-source phishing simulation tool
* **Railway** - Cloud deployment platform
* **GitHub** - Source code management
* **Mailtrap / Custom SMTP** - Email delivery service (optional)

##  Key Features

* Deployed Gophish using Railway with forked GitHub repository
* Configured `config.json` for public deployment
* Added trusted origins to bypass 403 Forbidden error
* Created and launched a test phishing campaign
* Tracked real-time user actions (email sent/opened/clicked/submitted)

## Steps Performed

1. **Forked Gophish Repository** from GitHub to personal account
2. **Deployed to Railway** using Railway's GitHub integration
3. **Edited `config.json`:**

   * Changed `listen_url` to `0.0.0.0:3333`
   * Set `use_tls` to `false`
   * Added Railway domain in `trusted_origins`
4. **Added Environment Variable** `PORT=3333` on Railway
5. **Launched Deployment** and verified admin panel login
6. **Created Phishing Campaign:**

   * Added target group and phishing email template
   * Configured landing page and sending profile
7. **Tracked Campaign Progress** through dashboard

## Campaign Screenshot

![image](https://github.com/user-attachments/assets/6d9eea46-a6f0-4545-97c4-8a5014affffe)


##  Learnings

* How phishing attacks are simulated in a secure environment
* Importance of security awareness training
* Gophish deployment, configuration, and debugging (e.g. `403 Forbidden` fix)
* Cloud deployment using Railway + GitHub CI

##  Live Admin Panel

https://gophish-production-6d1b.up.railway.app

##  Why This Project Matters

Phishing remains a top vector for cybersecurity breaches. This project helps organizations and individuals:

* Improve staff security awareness
* Test resilience to social engineering
* Understand attack patterns and countermeasures

##  Future Enhancements

* Connect Mailtrap or Gmail SMTP for real delivery
* Add realistic HTML templates for phishing
* Run multi-stage phishing simulations
* Generate reports and integrate with dashboards

##  References

* [Gophish Docs](https://docs.getgophish.com/)
* [Railway Hosting](https://railway.app/)
* [AlphaSec Blog Guide](https://alphasec.io/phishing-attack-simulation-gophish/)
