import os
from dotenv import load_dotenv


load_dotenv()


class Config:
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    BASE_URL = os.getenv("BASE_URL")
    MODEL = os.getenv("MODEL")
    
    TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    
    GMAIL_APPLICATION_CREDENTIALS = os.getenv("GMAIL_APPLICATION_CREDENTIALS")
    GMAIL_TOKEN = os.getenv("GMAIL_TOKEN")
    
    SOC_EMAIL_RECIPENT = os.getenv("SOC_EMAIL_RECIPENT")
    SOC_EMAIL_SENDER = os.getenv("SOC_EMAIL_SENDER")
    
    WEBHOOK_PORT = 8000
    DASHBOARD_PORT = 8501
    


    @classmethod
    def validate_required_config(cls):
        required_keys = [
            ("OPENAI_API_KEY",cls.OPENAI_API_KEY),
            ("TAVILY_API_KEY",cls.TAVILY_API_KEY),
            ("VIRUSTOTAL_API_KEY",cls.VIRUSTOTAL_API_KEY)
        ]
        
        missing_key = [key for key, value in required_keys if not value]
        
        if missing_key:
            raise ValueError(F"Faltan las siguientes variables de entorno: {', '.join(missing_key)}")
        
        return True   
        
        
        
config = Config()
        
        
        
        