# TFG — SOC casero (laboratorio reproducible)

Este repositorio contiene el código, configuraciones y evidencias asociadas a mi Trabajo de Fin de Grado, cuyo objetivo es diseñar, implementar y validar un **SOC casero** en un **laboratorio virtual reproducible**. El proyecto demuestra un flujo operativo completo de gestión de incidentes usando principalmente herramientas **open-source** y recursos limitados: **evento → alerta → correlación → ticket → notificación → respuesta → evidencias**.

---

##  Objetivo del proyecto

Construir y validar un laboratorio SOC que sea capaz de:

- Monitorizar y centralizar telemetría (logs) de distintos equipos.
- Detectar y **correlacionar** eventos repetitivos para reducir ruido.
- Convertir incidentes en **tickets operativos** (Jira) de forma automática.
- Enviar **notificaciones** (email y Telegram solo críticos).
- Aplicar **contención automática** en el endpoint (bloqueo de IP).
- Mantener **evidencias verificables** en cada fase del ciclo, orientadas a supervisión y trazabilidad coherentes con el enfoque de ISO/IEC 27001.

---

##  Arquitectura del laboratorio

El laboratorio se compone de **4 máquinas virtuales** con roles separados:

- **Kali Linux (Atacante)**: genera ataques controlados.
- **Windows 11 (Víctima / Endpoint)**: recibe ataques y genera eventos de seguridad.
- **Ubuntu Server (SOAR)**: ejecuta scripts de automatización, ticketing y notificaciones.
- **Servidor Wazuh (SIEM/XDR)**: centraliza, correlaciona y permite investigación (Manager + Dashboard + Indexer).

La red del laboratorio se mantiene en **Host-Only** con direccionamiento fijo en **192.168.56.0/24** para poder repetir pruebas consistentemente.

---

##  Flujo técnico (end-to-end)

1. **Ataque controlado** desde Kali hacia Windows (p. ej., fuerza bruta).
2. Windows genera **eventos** que son enviados por el **Wazuh Agent**.
3. Wazuh centraliza e indexa en **`wazuh-alerts-*`**.
4. Se aplican reglas y **correlación** para convertir eventos repetitivos en incidentes operativos (p. ej., `60122` → `100501`).
5. El **SOAR (Python)** consulta el Indexer, filtra, deduplica y **crea tickets en Jira**.
6. El SOAR notifica a **n8n**, que envía:
   - **Email** (canal general)
   - **Telegram** solo para incidentes críticos
7. **Active Response** ejecuta contención automática en Windows (bloqueo de IP con `netsh`).
8. Se recopilan evidencias: alertas indexadas, ticket, notificaciones y regla de firewall.

---

##  Estructura del repositorio

```text
tfg-soc-casero/
├─ README.md
├─ docs/
│  ├─ arquitectura.png
│  ├─ flujo_tecnico.png
│  ├─ modelo_datos.png
│  └─ evidencias/
│     ├─ windows_active_responses_excerpt.txt
│     └─ windows_firewall_rule.txt
├─ wazuh/
│  ├─ ossec.conf
│  ├─ local_rules.xml
│  ├─ opensearch.yml
│  └─ opensearch_dashboards.yml
├─ soar/
│  ├─ soar_create_ticket.py
│  ├─ soar_indexer_to_jira.py
│  ├─ soar_indexer_to_jira_correlated.py
│  ├─ requirements.txt
│  ├─ .env.example
│  └─ systemd/
│     ├─ soar-ticketing.service
│     └─ soar-ticketing.timer
└─ n8n/
   ├─ docker-compose.yml
   ├─ .env.example
   └─ workflows/
      └─ soc-alert-notify.json
```
##  Componentes principales

### Wazuh (SIEM/XDR)
- Centraliza telemetría y genera alertas.
- Mantiene evidencias indexadas en `wazuh-alerts-*`.
- Implementa correlación y **Active Response**.

**Archivos relevantes:** `wazuh/ossec.conf`, `wazuh/local_rules.xml`, `wazuh/opensearch.yml`, `wazuh/opensearch_dashboards.yml`.

---

### SOAR (Python)
- Consulta alertas en el Indexer.
- Filtra por agente/regla/severidad y aplica **deduplicación por ID**.
- Crea tickets en Jira con descripción estructurada (**ADF**).
- Dispara notificaciones a **n8n** vía webhook.

**Scripts:** `soar/soar_indexer_to_jira.py` y `soar/soar_create_ticket.py`.

---

### n8n (Notificaciones)
- Recibe un webhook desde el SOAR.
- Envía **email siempre**.
- Envía **Telegram solo en incidentes críticos** (según condición del workflow).

---

##  Instalación (Ubuntu SOAR)

### 1) Requisitos
- Python 3  
- (Opcional) `venv`  
- Acceso a Jira Cloud (email + token)  
- Acceso al Indexer de Wazuh (credenciales)  
- Docker (para n8n)

---

### 2) Instalar dependencias del SOAR
```bash
cd /opt/soar/ticketing
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
````md
##  Configurar variables de entorno


```bash
cp .env.example .env
nano .env
````
---

##  Ejecución manual del SOAR (prueba)

```bash
cd /opt/soar/ticketing
source .venv/bin/activate
python3 soar_indexer_to_jira.py
```

Si hay alertas nuevas que cumplan el filtro, se crearán tickets en Jira y se disparará notificación a n8n.

---

##  Ejecución automática (systemd)

Se incluye el servicio y el timer para ejecutar el SOAR cada minuto.

Copiar y activar (en Ubuntu SOAR):

```bash
sudo cp soar/systemd/soar-ticketing.service /etc/systemd/system/
sudo cp soar/systemd/soar-ticketing.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soar-ticketing.timer
```

Comprobar:

```bash
systemctl list-timers --all | grep soar-ticketing
journalctl -u soar-ticketing.service -n 50 --no-pager
```

---

##  Notificaciones con n8n

Levantar n8n (Ubuntu SOAR):

```bash
cd n8n
docker compose up -d
```

Acceso:

* `http://192.168.56.10:5678` (ajusta la IP a tu laboratorio)

Importar el workflow:

* `n8n/workflows/soc-alert-notify.json`

---

##  Evidencias

En `docs/evidencias/` se incluyen extractos verificables:

* ejecución de Active Response (`netsh`) en el log del agente
* regla de firewall creada con la IP bloqueada

Además, las evidencias operativas se complementan con:

* tickets generados en Jira
* executions de n8n
* consultas a `wazuh-alerts-*`

---

##  Seguridad y secretos

Este repositorio **no incluye secretos**.
Todo token/contraseña debe quedar fuera del repo y configurarse en `.env` local o en un gestor de secretos.

---

## Autor

Trabajo de Fin de Grado — Jorge Ferrero

```
```

