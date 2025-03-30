# pinguX
PinguX — your chill little auditor with sharp security claws 🐧🛡️

# 🐧 PinguX Roadmap (Mars → Août 2025)

Projet de scanner de sécurité Linux local & distant, avec extension Cloud et CI/CD. Roadmap alignée avec la montée en compétences DevSecOps / CloudSec de l'utilisateur.

---

## 🚀 Mars 2025 — PinguX Core: Audit local Linux

### ✅ Objectif : Créer les premiers modules de sécurité pour auditer une machine Linux locale

**Modules à développer :**
- [x] `ufw`: status, default policy, whitelist
- [x] `nftables`: table filter, hooks, drop policy
- [x] `ssh`: Port, PermitRootLogin, MaxAuthTries
- [ ] `users`: comptes root, sudoers, comptes sans mdp
- [ ] `services`: services critiques, ports ouverts
- [ ] `fail2ban`: actif ? patterns ? brute-force
- [ ] `journaux`: auth.log, connexions suspectes

**Objectifs techniques :**
- Parsing (configs, fichiers)
- `argparse`, `subprocess`, `regex`
- Rapport `.txt` ou `.json`
- Premiers fichiers modulaires

**✅ Fin mars :** audit complet local + rapport lisible

---

## 🔒 Avril 2025 — Hardening & structure

### ✅ Objectif : Finaliser la sécurité locale et créer un framework robuste

**Fonctionnalités :**
- Logging (verbose / quiet)
- Score global ou criticité par module
- Recommandations automatiques
- Loader dynamique des modules

**Technique :**
- CLI propre avec `--module` / `--all`
- Organisation en `modules/*.py`
- Gestion des erreurs si module absent

**✅ Fin avril :** outil modulaire, propre, extensible

---

## 🌐 Mai 2025 — Audit distant (via SSH)

### ✅ Objectif : Scanner une IP distante via SSH

**Fonctionnalités :**
- Connexion `paramiko`
- Envoi commandes à distance (UFW, SSH, etc.)
- `--remote` avec IP + user + clé SSH

**Technique :**
- Sécurité connexion SSH (timeouts, erreurs)
- Wrapper d'audit distant avec rapport

**✅ Fin mai :** PinguX scanne n'importe quel Linux distant

---

## ☁️ Juin 2025 — Premiers modules Cloud AWS

### ✅ Objectif : Auditer des EC2 AWS basiques (localement ou via boto3)

**Modules à ajouter :**
- Analyse Security Group (ports ouverts)
- IAM Role attaché à l'instance
- Volumes chiffrés ?

**Technique :**
- Apprentissage `boto3`
- Export des rapports JSON depuis le cloud

**✅ Fin juin :** extension cloud-ready

---

## 🛠️ Juillet 2025 — Packaging & transformation CLI tool

### ✅ Objectif : Transformer PinguX en outil installable

**Fonctionnalités :**
- `setup.py` ou `pyproject.toml`
- `pinguX` exécutable globalement via `pip`
- Fichiers `__init__.py` propres
- README + usage complet

**✅ Fin juillet :** outil Python portable et propre

---

## 🔐 Août 2025 — CI/CD + DevSecOps

### ✅ Objectif : Intégrer PinguX dans une pipeline CI/CD

**Fonctionnalités :**
- GitHub Actions: exécution auto de pinguX
- Upload du rapport JSON
- Lancement post-déploiement EC2
- Intégration d'autres outils: `checkov`, `bandit`, etc.

**✅ Fin août :** pipeline CI/CD avec vérification sécurité + rapport intégré

---

## 🌟 Vision long terme (optionnelle)
- Intégration API (FastAPI ?)
- Export Grafana / Prometheus
- Mode "daemon" d'audit en continu
- Interface web minimaliste

---
