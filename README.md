# crAPI × ByteHide Runtime — bundle autocontenido

Carpeta lista para entregar: **`git clone` + configurar `.env` + `docker compose up`**. Arranca crAPI
(la app vulnerable de OWASP, API Top-10) con **ByteHide Runtime** ya integrado en los tres servicios:

- **crapi-workshop** (Python/Django) → ByteHide Runtime (SDK Python)
- **crapi-chatbot** (Python/Quart + LLM) → ByteHide Runtime + **ByteHide AI Runtime** (protección del LLM)
- **crapi-identity** (Java/Spring Boot) → ByteHide Runtime (agente Java)

Los paquetes **ya vienen en el repo** (carpeta `packages/`); no hay que añadir nada a mano.
`docker compose` carga `docker-compose.yml` (crAPI) y **auto-mergea** `docker-compose.override.yml`
(la integración de ByteHide Runtime). No hacen falta flags `-f`.

## Contenido
```
crapi-bytehide/
├─ docker-compose.yml            # crAPI (imágenes oficiales de Docker Hub)
├─ docker-compose.override.yml   # integración ByteHide Runtime (auto-cargada)
├─ Dockerfile.bh-python          # workshop + chatbot (ByteHide Runtime, SDK Python)
├─ Dockerfile.bh-identity        # identity (ByteHide Runtime, agente Java)
├─ .env.example                  # plantilla de variables de entorno
├─ packages/                     # YA INCLUIDOS, no hay que tocar nada
│  ├─ bytehide_monitor-0.1.0-py3-none-any.whl   # ByteHide Runtime — SDK Python (workshop + chatbot)
│  ├─ monitor-java-agent-1.0.4.jar              # ByteHide Runtime — agente Java (identity)
│  └─ monitor.json                              # configuración del runtime
├─ attack/                       # harness de validación (reproduce los retos de crAPI)
│  ├─ crapi_attacks_full.py      # harness exhaustivo (recomendado)
│  └─ crapi_attacks.py           # harness reducido
└─ keys/                         # llaves JWT de crapi-identity (se generan en runtime)
```

## Paso 1 — Configurar el entorno
Copia la plantilla y rellena las variables:
```bash
cp .env.example .env
```
Edita `.env` y pon, como mínimo:

| Variable | Para qué |
|---|---|
| `MONITOR_PYTHON_KEY` | token del proyecto ByteHide de los servicios **Python** (workshop + chatbot) |
| `MONITOR_JAVA_KEY` | token del proyecto ByteHide del servicio **Java** (identity) |
| `CHATBOT_LLM_PROVIDER` | proveedor del LLM del chatbot (por defecto `openai`) |
| `CHATBOT_OPENAI_API_KEY` | API key del proveedor — necesaria para los retos LLM 16-18 |

(El resto de variables del `.env.example` son opcionales: heartbeat, debug, puertos…)

## Paso 2 — Levantar todo (primera vez)
```bash
docker compose up -d --build
```
- Web/API: **http://localhost:8888**
- Bandeja de correo (OTP del reto 3): http://localhost:8025

Comprobar que ByteHide Runtime arrancó:
```bash
docker compose logs crapi-workshop | grep -i bytehide
docker compose logs crapi-identity | grep -i "HB_START\|javaagent"
```

## Paso 3 — Probar que la API funciona
Abre **http://localhost:8888** en el navegador y registra/inicia sesión. Si la UI carga y responde,
crAPI está en marcha con ByteHide Runtime integrado. No hay que tocar nada más.

## Paso 4 — Validar la protección con el harness de ataques
Desde la raíz de esta carpeta:
```bash
pip install requests          # única dependencia del harness
python3 attack/crapi_attacks_full.py
```
El harness reproduce los retos de crAPI y marca cada uno como **BLOCKED** (ByteHide lo paró), **VULN**
(el ataque tuvo éxito) o **FAIL** (no se pudo reproducir). Lee la API key del LLM del `.env`
automáticamente, así que los retos 16-18 funcionan sin configurar nada extra.

> ⚠️ **Importante — reglas en modo block.** Para que los ataques salgan como **BLOCKED**, el proyecto de
> ByteHide Runtime que hayas puesto en el `.env` tiene que tener sus reglas/detectores en modo **block**
> (no en `log`/`observe`). En `log`, ByteHide los **detecta pero no los bloquea** → el harness los verá
> como VULN/FAIL. Las acciones (block ↔ log) se ajustan en la política del proyecto, en el panel de
> ByteHide Runtime; el cambio llega en el siguiente heartbeat.

> ⚠️ **Importante — retos LLM (16-18).** El proyecto de ByteHide Runtime debe tener activada la regla de
> **AI Security** con una política que **bloquee prompt injection** (ByteHide AI Runtime). Sin esa política,
> el chatbot no detendrá los ataques de prompt-injection y esos retos no saldrán como BLOCKED.

## Limitaciones conocidas
Algunos retos de crAPI no se bloquean en esta integración:

- **Reto 12 — NoSQL injection** (servicio *community*, escrito en Go): no se detecta porque todavía no se incluye el paquete de ByteHide Runtime para Go.
- **Reto 1 — BOLA (ubicación de vehículo)** y **Reto 10 — Mass-assignment de propiedad de vídeo**
  (`conversion_params`): limitaciones conocidas del runtime de Java —en proceso de portado desde la
  versión de Python, estarán disponibles próximamente— o que requieren tener activo **Behavior Analysis**
  en el proyecto de ByteHide Runtime.

## Reconstruir tras un cambio
Si cambias el `.env`, un paquete de `packages/`, un Dockerfile o el compose, reconstruye y recrea:
```bash
docker compose up -d --build --force-recreate
```
Para un solo servicio (p. ej. el chatbot):
```bash
docker compose up -d --build crapi-chatbot
```

## Notas
- `crapi-identity` monta `./keys`; las llaves se generan solas en el primer arranque.
- Si el host ya usa los puertos 8888/8025/5500, edítalos en `docker-compose.yml` (o por `.env`).
- No commitees el `.env` real (ya está en `.gitignore`); sí el `.env.example`.
