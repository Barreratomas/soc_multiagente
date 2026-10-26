import vt
from langchain_tavily import TavilySearch
from langchain_google_community import GmailToolkit
from langchain_google_community.gmail.utils import get_google_credentials, build_gmail_service
from langchain.tools import tool
from datetime import datetime

from config import config




# valida configuracion al importar
config.validate_required_config()

#  tool de busqeuda
search_tool = TavilySearch(
    max_results = 3,
    api_key=config.TAVILY_API_KEY
)


# tools de gmail
creds = get_google_credentials(
    token_file=config.GMAIL_TOKEN,
    client_secrets_file=config.GMAIL_APPLICATION_CREDENTIALS,
    scopes=["https://mail.google.com/"]
)

gmail_tookit = GmailToolkit(api_resource=build_gmail_service(credentials=creds))
gmail_tools =  gmail_tookit.get_tools()


# virustotal tool
@tool
def virustotal_checker(indicator:str, indicator_type:str)->str:
    """analiza urls, ips y hashes usando la api de virus total.
    
    Args:
        indicator:URL, IP o hash a analizar.
        indicator_type:'url', 'ip' o 'hash'
        
    Returns:
        Resultado del analisis de Virustotal
    """
    try:
        with vt.Client(config.VIRUSTOTAL_API_KEY) as client:
            if indicator_type == "url":
               url_id = vt.url_id(indicator)
               analysis = client.get_object(f"/urls/{url_id}")
            elif indicator_type == 'ip':
                analysis = client.get_object(f"ip-addresses/{indicator}")
            elif indicator_type == 'hash':
                analysis = client.get_object(f"files/{indicator}")
            else:
                return f"Tipo no soportado: {indicator_type}"
            status = analysis.last_analysis_stats
            
            malicious = status.get("malicious", 0)
            suspicious = status.get("suspicious", 0)
            total = sum(status.values())
    
    
            if malicious > 5:
                threat_level = "Malicioso"
            elif suspicious > 0 or suspicious > 3:
                threat_level = "Sospechoso"
            else:
                threat_level = "Limpio"
                
            return f"""ANALISIS VIRUSTOTAL:
Indicador: {indicator}
Detecciones: {malicious}/{total} maliciosas, {suspicious}/{total} sospechosas
Clasificacion: {threat_level}
Análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
    
    except Exception as e:
        return f"Error virustotal: {e}"

all_tools = [search_tool, virustotal_checker, gmail_tools]
    
    
    