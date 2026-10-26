from langchain_openai import ChatOpenAI
from langgraph_supervisor import create_supervisor
from datetime import datetime
import json

from agent import alert_analyzer,threat_analyzer, notification_agent 
from config import config



supervisor_model = ChatOpenAI(
    model=config.MODEL,
    api_key=config.OPENAI_API_KEY,
    base_url=config.BASE_URL,
    temperature=0.1
    
)

def build_soc_workflow():
    # crear el supervisor multiagente
    supervisor=create_supervisor(
        agents=[alert_analyzer,threat_analyzer, notification_agent],
        model=supervisor_model,
        prompt="""Sos el supervisor del SOC que coordina EXACTAMENTE 3 pasos secuenciales.

    AGENTES DISPONIBLES:
    1. **alert_analyzer**: Analiza IOCs y determina VERDADERO/FALSO POSITIVO
    2. **threat_analyzer**: Evalúa severidad y propone mitigación (solo para verdaderos positivos)  
    3. **notification_agent**: Envía email final con resultados

    FLUJO OBLIGATORIO - NO DESVIAR:
    1. PASO 1: Delegar a "alert_analyzer" para análisis inicial
    2. PASO 2: Si VERDADERO POSITIVO → "threat_analyzer" | Si FALSO POSITIVO → saltar a paso 3
    3. PASO 3: Delegar a "notification_agent" para envío final
    4. FINALIZAR: Cuando notification_agent complete, TERMINAR inmediatamente

    REGLAS CRÍTICAS:
    - NO HACER análisis propio - solo coordinar agentes
    - NUNCA volver a un agente ya ejecutado
    - TERMINAR después del notification_agent
    - NO continuar después de enviar email
    - Máximo 3 delegaciones por alerta

    FORMATO DE DELEGACIÓN:
    - "Delegando a alert_analyzer para..."
    - "Delegando a threat_analyzer para..." 
    - "Delegando a notification_agent para..."
    - "PROCESO COMPLETADO"

    Si un agente ya fue ejecutado, NO volver a ejecutarlo.""",
    add_handoff_back_messages=True,
    output_mode='full_history'
    )

    return supervisor.compile()

# insntacia del workflow del supervisor
soc_workflow = build_soc_workflow()

def process_security_alert(alert_data:dict, incident_id:str, processing_context:dict = None)-> dict:
    if processing_context is None:
        processing_context = {}
    
    initial_message = f"""ALERTA SOC PARA PROCESAMIENTO SECUENCIAL:

    ID: {incident_id}
    DATOS: {json.dumps(alert_data, indent=2)}
    EMAIL: {processing_context.get('email_recipient', 'engineer.education.colab@gmail.com')}

    INSTRUCCIÓN CLARA: Ejecutar EXACTAMENTE estos 3 pasos:
    1. alert_analyzer → análisis IOCs y determinar VERDADERO/FALSO POSITIVO
    2. SI verdadero positivo → threat_analyzer → evaluación severidad y mitigación  
    3. notification_agent → envío email final

    TERMINAR después del paso 3. NO continuar."""
    
    print(f"Iniciando arquitectura supervisor para {incident_id}")
    print(f"Supervisor coordina: alert_analyzer -> threat_analyzer->notification_agent")
    print(f"usando apis de: virustotal, gmail y tavilySearch")

    try:
        # ejecutar workflow del supervisor
        result = soc_workflow({
            "message":[{"role":"user","content":initial_message}]
        })

        # extraer los resultado de cada agente del historial de mensajes
        analysis_result = _extract_agent_result(result, "alert_analyzer")
        threat_result= _extract_agent_result(result, "threat_analyzer")
        notification_result= _extract_agent_result(result, "notification_agent")

        # determina las herramientas utilizadas para los resultados
        tools_used = ["langgraph-supervisor", "create_supervisor"]
        
        if analysis_result and ("VIRUSTOTAL" in analysis_result or "VirusTotal" in analysis_result):
            tools_used.append("VirusTotal API")
            
        if analysis_result or threat_result:
            tools_used.append("TavilySearch API")
            
        if notification_result and ("GMAIL" in notification_result or "Email" in notification_result):
            tools_used.append("Gmail API")
            
            
            
        final_result = {
            "incident_id":incident_id,
            "status":"completed",
            "analysis_result":analysis_result or "No analysis result",
            "threat_assesment": threat_result or "No threat assesment performed",
            "notification_sent":notification_result or "No notification sent",
            "timestamp": datetime.now().isocalendar(),
            "tools_used": tools_used,
            "supervisor_architecture":True,
            "apis_real":True,
            "processing_context":processing_context,
            "full_conversation":result.get("messages",[])
        }
        return final_result
    
    
    except Exception as e:
        print(f"Error en arquitectura supervisor: {e}")
        
        error_result = {
            "incident_id":incident_id,
            "status":"error",
            "error":e,
            "timestamp": datetime.now().isocalendar(),
            "supervisor_architecture":True,
            "apis_real":True,
        }
        return error_result



def _extract_agent_result(workflow_result:dict, agent_name:str)->str:
    try:
        messages = workflow_result.get("messages",[])
        
        agent_messages = []
        for message in messages:
            if hasattr(message,'content') and agent_name in str(message).lower():
                agent_messages.append(message.content)
            elif isinstance(message,dict):
                content = message.get('content','')
                if agent_name in str(message).lower() or agent_name in content.lower():
                    agent_messages.append(content)

        # retorna el ultimo mensaje del agente o concatena si hay multiples
        if agent_messages:
            return agent_messages[-1] if len(agent_messages) == 1 else "\n\n".join(agent_messages)
        
        return ""
    
    except Exception as e:
        print(f"Error extrayendo el resultado del agente: {agent_name}: {e}")
        return ""