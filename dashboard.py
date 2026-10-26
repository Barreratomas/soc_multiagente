import streamlit as st
import requests
import time
from datetime import datetime, timedelta

st.set_page_config(
    page_title="SOC Multi-Agent Dashboard",
    layout="wide"
)

# Inicializar session_state
if 'processing_alerts' not in st.session_state:
    st.session_state.processing_alerts = {}
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

# Funciones auxiliares
def get_server_status():
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        return response.status_code == 200, response.json() if response.status_code == 200 else None
    except:
        return False, None

def get_incidents():
    try:
        response = requests.get("http://localhost:8000/incidents", timeout=10)
        if response.status_code == 200:
            return response.json().get("incidents", [])
    except:
        pass
    return []

def check_alert_status(incident_id):
    incidents = get_incidents()
    for incident in incidents:
        if incident.get('incident_id') == incident_id:
            return incident
    return None

def format_timestamp(ts_string):
    try:
        dt = datetime.fromisoformat(ts_string.replace('Z', '+00:00'))
        return dt.strftime('%H:%M:%S - %d/%m/%Y')
    except:
        return ts_string

# Header
st.title("SOC Multi-Agent Security Dashboard")
st.markdown("**Sistema de Operaciones de Seguridad con APIs Reales**")

# Auto-refresh control
col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    st.markdown(f"**Última actualización:** {st.session_state.last_refresh.strftime('%H:%M:%S')}")
with col2:
    if st.button("Actualizar Ahora", key="manual_refresh"):
        st.session_state.last_refresh = datetime.now()
        st.rerun()
with col3:
    st.session_state.auto_refresh = st.toggle("Auto-refresh", value=st.session_state.auto_refresh)

st.markdown("---")

# Estado del Sistema
st.subheader("Estado del Sistema")

server_online, health_data = get_server_status()
incidents = get_incidents()
processing_count = len([i for i in incidents if i.get('status') == 'processing'])

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    if server_online:
        st.metric("Servidor", "ONLINE")
    else:
        st.metric("Servidor", "OFFLINE")

with col2:
    st.metric("Total Incidentes", f"{len(incidents)}", delta=f"+{len([i for i in incidents if (datetime.now() - datetime.fromisoformat(i.get('timestamp', '2000-01-01T00:00:00'))).seconds < 3600])}")

with col3:
    completed = len([i for i in incidents if i.get('status') == 'completed'])
    st.metric("Completados", f"{completed}", delta=f"{completed}/{len(incidents) if incidents else 0}")

with col4:
    st.metric("Procesando", f"{processing_count}")

with col5:
    errors = len([i for i in incidents if i.get('status') == 'error'])
    st.metric("Errores", f"{errors}")

if health_data:
    with st.expander("Detalles del Estado del Sistema"):
        col1, col2 = st.columns(2)
        with col1:
            st.write("**APIs Configuradas:**")
            api_config = health_data.get('api_configuration', {})
            for api, status in api_config.items():
                st.write(f"- {api.replace('_', ' ').title()}: {status}")
        with col2:
            st.write("**Estadísticas:**")
            st.write(f"- Incidentes procesados: {health_data.get('total_incidents_processed', 0)}")
            st.write(f"- Estado general: {health_data.get('status', 'unknown').upper()}")

st.markdown("---")

# Formulario de alerta
st.subheader("Centro de Análisis de Amenazas")

with st.form("alert_form", clear_on_submit=True):
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Información Básica**")
        alert_type = st.selectbox(
            "Tipo de Amenaza",
            ["Malware Detection", "Phishing Attempt", "Unauthorized Access", "Port Scan", "Suspicious Activity"]
        )
        severity = st.selectbox("Nivel de Severidad", ["Critical", "High", "Medium", "Low"])
        source_ip = st.text_input("IP Origen", value="", placeholder="ej: 192.168.1.100")
    
    with col2:
        st.markdown("**Indicadores de Compromiso (IOCs)**")
        destination_ip = st.text_input("IP Destino (opcional)", placeholder="ej: 10.0.0.5")
        url = st.text_input("URL Sospechosa (opcional)", placeholder="ej: http://malicious-site.com")
        file_hash = st.text_input("Hash de Archivo (opcional)", placeholder="SHA256/MD5/SHA1")
    
    st.markdown("**Detalles Adicionales**")
    col3, col4 = st.columns(2)
    
    with col3:
        message = st.text_area("Descripción del Incidente", 
                             value="", 
                             placeholder="Describe la actividad sospechosa detectada...",
                             height=100)
    
    with col4:
        email_recipient = st.text_input("Email para Notificaciones", 
                                      placeholder="soc-team@empresa.com")
        priority = st.radio("Prioridad de Procesamiento", 
                          ["Normal", "Urgente"], 
                          horizontal=True)
    
    # Botón de envío grande y claro
    submitted = st.form_submit_button("Iniciar Análisis de Amenaza", 
                                    use_container_width=True, 
                                    type="primary")
    
    if submitted:
        # Validación básica
        if not source_ip and not url and not file_hash:
            st.error("Debes proporcionar al menos un IOC: IP, URL o Hash")
        else:
            alert_payload = {
                "source": "dashboard_advanced",
                "alert_type": alert_type,
                "severity": severity,
                "message": message or f"Análisis de {alert_type.lower()}",
                "source_ip": source_ip or None,
                "destination_ip": destination_ip or None,
                "url": url or None,
                "file_hash": file_hash or None,
                "email_recipient": email_recipient or None,
                "priority": priority,
                "timestamp": datetime.now().isoformat(),
                "real_apis": True
            }
            
            with st.spinner("Enviando alerta al sistema de análisis..."):
                try:
                    response = requests.post(
                        "http://localhost:8000/webhook/alert",
                        json=alert_payload,
                        timeout=15
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        incident_id = result['incident_id']
                        
                        # Guardar en session_state para tracking
                        st.session_state.processing_alerts[incident_id] = {
                            'start_time': datetime.now(),
                            'alert_type': alert_type,
                            'severity': severity
                        }
                        
                        st.success(f"**Análisis iniciado:** {incident_id}")
                        
                        # Mostrar información de seguimiento
                        with st.expander("Información del Análisis", expanded=True):
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.write(f"**ID:** {incident_id}")
                                st.write(f"**Severidad:** {severity}")
                            with col2:
                                st.write(f"**Tipo:** {alert_type}")
                                st.write(f"**Iniciado:** {datetime.now().strftime('%H:%M:%S')}")
                            with col3:
                                st.write(f"**Email:** {email_recipient or 'Por defecto'}")
                                st.write(f"**Prioridad:** {priority}")
                        
                        st.info("**El análisis está en progreso.** Los resultados aparecerán automáticamente en el panel inferior en 45-90 segundos.")
                        
                    else:
                        st.error(f"Error del servidor: {response.text}")
                        
                except requests.exceptions.Timeout:
                    st.warning("**El servidor está tardando en responder.** Esto es normal durante picos de procesamiento. El análisis puede haber comenzado correctamente.")
                except requests.exceptions.ConnectionError:
                    st.error("**No se puede conectar al servidor.** Verifica que el webhook esté ejecutándose: `python webhook_server.py`")
                except Exception as e:
                    st.error(f"Error inesperado: {str(e)}")

st.markdown("---")

# Panel de monitoreo en tiempo real
st.subheader("Monitor de Análisis en Tiempo Real")

# Check processing alerts
active_alerts = []
completed_since_last = []

for incident_id, alert_info in st.session_state.processing_alerts.items():
    current_status = check_alert_status(incident_id)
    
    if current_status:
        time_elapsed = (datetime.now() - alert_info['start_time']).seconds
        
        if current_status.get('status') == 'completed':
            if incident_id not in [a.get('incident_id') for a in completed_since_last]:
                completed_since_last.append(current_status)
        elif time_elapsed < 300:  # 5 minutos
            active_alerts.append({
                **current_status,
                'time_elapsed': time_elapsed,
                'alert_info': alert_info
            })

# Mostrar alertas activas
if active_alerts:
    st.markdown("**Análisis en Progreso:**")
    for alert in active_alerts:
        incident_id = alert.get('incident_id', 'N/A')
        time_elapsed = alert.get('time_elapsed', 0)
        alert_info = alert.get('alert_info', {})
        
        with st.container():
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            
            with col1:
                st.write(f"**{incident_id}**")
                st.caption(f"{alert_info.get('alert_type', 'N/A')} - {alert_info.get('severity', 'N/A')}")
            
            with col2:
                progress = min(time_elapsed / 90, 1.0)  # 90 segundos esperados
                st.progress(progress)
                st.caption(f"{time_elapsed}s transcurridos")
            
            with col3:
                if time_elapsed < 30:
                    st.info("Analizando IOCs")
                elif time_elapsed < 60:
                    st.info("Evaluando amenazas")
                elif time_elapsed < 90:
                    st.info("Enviando notificación")
                else:
                    st.warning("Finalizando...")
            
            with col4:
                if st.button("Ver Detalles", key=f"view_{incident_id}"):
                    with st.expander(f"Detalles de {incident_id}", expanded=True):
                        st.json(alert)

# Mostrar alertas completadas recientemente
if completed_since_last:
    st.success("**Análisis Completados Recientemente:**")
    for alert in completed_since_last[-3:]:  # Últimos 3
        incident_id = alert.get('incident_id', 'N/A')
        
        with st.container():
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                st.write(f"**{incident_id}** - Completado")
            
            with col2:
                # Determinar resultado basado en el contenido
                analysis = alert.get('analysis_result', '')
                if 'VERDADERO POSITIVO' in analysis:
                    st.error("Verdadero Positivo")
                elif 'FALSO POSITIVO' in analysis:
                    st.success("Falso Positivo")
                else:
                    st.info("Análisis completo")
            
            with col3:
                if st.button("Ver Reporte", key=f"report_{incident_id}"):
                    st.session_state[f"show_report_{incident_id}"] = True

# Historial de incidentes
st.markdown("---")
st.subheader("Historial de Incidentes")

# Filtros
col1, col2, col3, col4 = st.columns(4)
with col1:
    status_filter = st.selectbox("Estado", ["Todos", "completed", "error", "processing"])
with col2:
    time_filter = st.selectbox("Período", ["Última hora", "Últimas 24h", "Última semana", "Todo"])
with col3:
    limit = st.number_input("Mostrar últimos", min_value=5, max_value=50, value=10)
with col4:
    sort_order = st.selectbox("Orden", ["Más recientes", "Más antiguos"])

# Aplicar filtros
filtered_incidents = incidents.copy()

if status_filter != "Todos":
    filtered_incidents = [i for i in filtered_incidents if i.get('status') == status_filter]

if time_filter != "Todo":
    now = datetime.now()
    if time_filter == "Última hora":
        cutoff = now - timedelta(hours=1)
    elif time_filter == "Últimas 24h":
        cutoff = now - timedelta(days=1)
    else:  # Última semana
        cutoff = now - timedelta(weeks=1)
    
    filtered_incidents = [i for i in filtered_incidents 
                         if datetime.fromisoformat(i.get('timestamp', '2000-01-01T00:00:00')) > cutoff]

# Ordenar
filtered_incidents = sorted(filtered_incidents, 
                           key=lambda x: x.get('timestamp', ''), 
                           reverse=(sort_order == "Más recientes"))[:limit]

# Mostrar incidentes
if filtered_incidents:
    st.write(f"**Mostrando {len(filtered_incidents)} incidentes**")
    
    for incident in filtered_incidents:
        incident_id = incident.get('incident_id', 'N/A')
        timestamp = incident.get('timestamp', 'N/A')
        status = incident.get('status', 'unknown')
        tools_used = incident.get('tools_used', [])
        
        # Determinar etiqueta y color
        if status == 'completed':
            status_tag = "[OK]"
            status_color = "success"
        elif status == 'error':
            status_tag = "[ERROR]"
            status_color = "error"
        else:
            status_tag = "[EN CURSO]"
            status_color = "info"

        with st.expander(f"{status_tag} {incident_id} - {format_timestamp(timestamp)}",
                       expanded=False):
            
            # Resumen en columnas
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**Estado**")
                st.write(f"Status: {status.upper()}")
                st.write(f"APIs: {len(tools_used)}")
                
            with col2:
                st.markdown("**Análisis**")
                analysis = incident.get('analysis_result', '')
                if 'VERDADERO POSITIVO' in analysis:
                    st.error("Verdadero Positivo")
                elif 'FALSO POSITIVO' in analysis:
                    st.success("Falso Positivo")
                elif analysis and analysis != "Análisis no encontrado":
                    st.info("Completado")
                else:
                    st.warning("Pendiente")
            
            with col3:
                st.markdown("**Notificación**")
                notification = incident.get('notification_sent', '')
                if 'EMAIL ENVIADO' in notification:
                    st.success("Enviado")
                elif 'Error' in notification:
                    st.error("Error")
                else:
                    st.warning("Pendiente")
            
            # Herramientas utilizadas
            if tools_used:
                st.markdown("**Herramientas Utilizadas:**")
                tool_cols = st.columns(min(len(tools_used), 4))
                for i, tool in enumerate(tools_used):
                    with tool_cols[i % 4]:
                        if "VirusTotal" in tool:
                            st.success("VirusTotal")
                        elif "Gmail" in tool:
                            st.success("Gmail")
                        elif "Tavily" in tool:
                            st.success("TavilySearch")
                        elif "AbuseIPDB" in tool:
                            st.success("AbuseIPDB")
                        else:
                            st.info(f"{tool}")
            
            # Botón para detalles completos
            col1, col2 = st.columns([1, 3])
            with col1:
                if st.button("Ver JSON Completo", key=f"json_{incident_id}"):
                    st.json(incident)

else:
    st.info("No hay incidentes que coincidan con los filtros seleccionados")

# Auto-refresh
if st.session_state.auto_refresh and server_online:
    time.sleep(5)
    st.rerun()

# Footer
st.markdown("---")
st.markdown("**SOC Multi-Agent Dashboard v2.0** | Powered by langgraph-supervisor")
st.caption(f"Última actualización automática: {datetime.now().strftime('%H:%M:%S')}")