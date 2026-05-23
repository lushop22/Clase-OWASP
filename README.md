# OWASP Top 10:2025 — Labs Interactivos

Demo educativa con backend Express.js funcional + frontend para las 5 categorías más críticas del OWASP Top 10:2025.

## Requisitos

- Docker Engine 20+
- Docker Compose v2

## Levantar los labs

```bash
docker compose up --build
```

Primera vez tarda ~3-5 min (build de imágenes). Luego abre **http://localhost:8080** para el portal.

## Mapa de puertos

| Puerto | Lab                                   | OWASP 2025 | Modo       |
|--------|---------------------------------------|------------|------------|
| 8080   | Portal de inicio                      | —          | —          |
| 3001   | Broken Access Control (IDOR)          | **A01**    | Vulnerable |
| 3002   | Broken Access Control (IDOR)          | **A01**    | Seguro     |
| 3003   | Security Misconfiguration             | **A02**    | Vulnerable |
| 3004   | Security Misconfiguration             | **A02**    | Seguro     |
| 3005   | Software Supply Chain Failures        | **A03** 🆕 | Vulnerable |
| 3006   | Software Supply Chain Failures        | **A03** 🆕 | Seguro     |
| 3007   | Cryptographic Failures                | **A04**    | Vulnerable |
| 3008   | Cryptographic Failures                | **A04**    | Seguro     |
| 3009   | Injection (SQL Injection)             | **A05**    | Vulnerable |
| 3010   | Injection (SQL Injection)             | **A05**    | Seguro     |

## Vulnerabilidades y ataques

| OWASP 2025 | Lab              | Ataque demostrado                                          |
|------------|------------------|------------------------------------------------------------|
| A01        | IDOR             | Cambiar `?id=` para acceder a perfiles ajenos              |
| A02        | Misconfiguration | `/debug` expuesto, stack traces, panel admin sin auth       |
| A03 🆕     | Supply Chain     | Prototype Pollution via merge vulnerable (CVE-2019-10744)  |
| A04        | Cryptographic    | MD5 crackeado con rainbow table vs. bcrypt (infactible)    |
| A05        | SQL Injection    | `' OR '1'='1' --` bypass + UNION dump de la base de datos  |

## Diferencias vs. OWASP 2021

| 2021        | 2025 | Cambio                                     |
|-------------|------|--------------------------------------------|
| A01 BAC     | A01  | Mantiene #1                                |
| A05 Misconf | A02  | Sube de A05 → A02                          |
| —           | A03  | **NUEVO**: Supply Chain Failures           |
| A02 Crypto  | A04  | Baja de A02 → A04                          |
| A03 Inject  | A05  | Baja de A03 → A05                          |

## Detener

```bash
docker compose down
```

## Uso educativo únicamente — no desplegar en producción.
