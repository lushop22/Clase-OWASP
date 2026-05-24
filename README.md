# OWASP Top 10:2025 — Labs Interactivos

Demo educativa con backend Express.js funcional + frontend para las 5 categorías más críticas del OWASP Top 10:2025.

## Requisitos

- Docker Engine 20+
- Docker Compose v2

## Configuración del dominio

Antes de levantar los labs, editá el archivo `.env` en la raíz del proyecto:

```env
DOMAIN=owasp.local
```

Cambiá `owasp.local` por el dominio que corresponda (ej. `tudominio.com` en un servidor real). Todos los servicios y el portal usarán ese valor automáticamente.

### Hosts locales (solo para desarrollo)

Si usás el dominio por defecto `owasp.local`, agregá estas líneas al archivo de hosts de tu máquina:

**Linux/macOS** — `/etc/hosts`  
**Windows** — `C:\Windows\System32\drivers\etc\hosts` (abrir como Administrador)

```
127.0.0.1  portal.owasp.local
127.0.0.1  idor-vuln.owasp.local
127.0.0.1  idor-fixed.owasp.local
127.0.0.1  misconfig-vuln.owasp.local
127.0.0.1  misconfig-fixed.owasp.local
127.0.0.1  supply-chain-vuln.owasp.local
127.0.0.1  supply-chain-fixed.owasp.local
127.0.0.1  crypto-vuln.owasp.local
127.0.0.1  crypto-fixed.owasp.local
127.0.0.1  sqli-vuln.owasp.local
127.0.0.1  sqli-fixed.owasp.local
```

## Levantar los labs

```bash
docker compose up --build -d
```

Primera vez tarda ~3-5 min (build de imágenes). Luego abre **http://portal.owasp.local** en el browser.

## Mapa de dominios

Todo el tráfico entra por el **puerto 80** a través del proxy Nginx y se enruta por nombre de dominio.

| Dominio                          | Lab                            | OWASP 2025 | Modo       |
|----------------------------------|--------------------------------|------------|------------|
| portal.`DOMAIN`                  | Portal de inicio               | —          | —          |
| idor-vuln.`DOMAIN`               | Broken Access Control (IDOR)   | **A01**    | Vulnerable |
| idor-fixed.`DOMAIN`              | Broken Access Control (IDOR)   | **A01**    | Seguro     |
| misconfig-vuln.`DOMAIN`          | Security Misconfiguration      | **A02**    | Vulnerable |
| misconfig-fixed.`DOMAIN`         | Security Misconfiguration      | **A02**    | Seguro     |
| supply-chain-vuln.`DOMAIN`       | Software Supply Chain Failures | **A03** 🆕 | Vulnerable |
| supply-chain-fixed.`DOMAIN`      | Software Supply Chain Failures | **A03** 🆕 | Seguro     |
| crypto-vuln.`DOMAIN`             | Cryptographic Failures         | **A04**    | Vulnerable |
| crypto-fixed.`DOMAIN`            | Cryptographic Failures         | **A04**    | Seguro     |
| sqli-vuln.`DOMAIN`               | Injection (SQL Injection)      | **A05**    | Vulnerable |
| sqli-fixed.`DOMAIN`              | Injection (SQL Injection)      | **A05**    | Seguro     |

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

## Arquitectura

```
Browser → *.DOMAIN:80
              ↓
         [Nginx proxy]  ← único puerto expuesto al host
              ↓ (ruteo por Host header)
         Contenedor del servicio correspondiente
```

## Detener

```bash
docker compose down
```

## Uso educativo únicamente — no desplegar en producción.
