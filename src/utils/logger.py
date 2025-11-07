import logging
from datetime import datetime
import os

def setup_logger(log_file='scanner.log'):
    
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logger = logging.getLogger('WebScanner')
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler = logging.FileHandler(os.path.join(log_dir, log_file))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def log_vulnerability(logger, vuln_type, url, payload=None, parameter=None, details=None):
    message = f"Vulnerabilidade encontrada - Tipo: {vuln_type}, URL: {url}"
    if payload:
        message += f", Payload: {payload}"
    if parameter:
        message += f", Parâmetro: {parameter}"
    if details:
        message += f", Detalhes: {details}"
    
    logger.warning(message)