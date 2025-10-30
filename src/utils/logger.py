"""
Módulo para gerenciamento de logs
"""
import logging
from datetime import datetime
import os

def setup_logger(log_file='scanner.log'):
    """Configura o logger com formato personalizado"""
    
    # Cria o diretório de logs se não existir
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configura o logger
    logger = logging.getLogger('WebScanner')
    logger.setLevel(logging.INFO)
    
    # Formato do log
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler para arquivo
    file_handler = logging.FileHandler(os.path.join(log_dir, log_file))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Handler para console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def log_vulnerability(logger, vuln_type, url, payload=None, parameter=None, details=None):
    """Registra uma vulnerabilidade encontrada"""
    message = f"Vulnerabilidade encontrada - Tipo: {vuln_type}, URL: {url}"
    if payload:
        message += f", Payload: {payload}"
    if parameter:
        message += f", Parâmetro: {parameter}"
    if details:
        message += f", Detalhes: {details}"
    
    logger.warning(message)