from flask import Flask, render_template, request, send_from_directory, url_for
import os
import requests
from urllib.parse import quote as url_quote, urlparse
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
google_api_key = os.getenv('GOOGLE_API_KEY')
virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

# Função para verificar HTTPS
def check_https(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https":
        return "O site não está utilizando HTTPS!"
    return "O site está utilizando HTTPS."

# Função para verificar headers de segurança
def check_security_headers(url):
    headers_to_check = {
        "Content-Security-Policy": "Protege contra XSS e injeções de dados.",
        "X-Content-Type-Options": "Previne ataques de MIME-sniffing.",
        "X-Frame-Options": "Previne ataques de clickjacking.",
        "Strict-Transport-Security": "Garante que o site só será acessado por HTTPS."
    }
    
    response = requests.get(url)
    missing_headers = []
    
    for header, description in headers_to_check.items():
        if header not in response.headers:
            missing_headers.append(f"{header} está faltando. {description}")
    
    return missing_headers if missing_headers else "Todos os headers de segurança estão presentes."

# Função para verificar URL com Google Safe Browsing API
def check_google_safe_browsing(api_key, url):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": api_key}
    payload = {
        "client": {
            "clientId": "myapp",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload, params=params)
    result = response.json()
    return "URL Testada: Status Seguro!" if not result.get("matches") else "URL Testada: Status Maliciosa"

# Função para verificar URL com VirusTotal API
def check_virustotal(api_key, url):
    # Codificar a URL e preparar o cabeçalho com a API Key
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_quote(url)}"
    headers = {"x-apikey": api_key}
    
    # Fazer a requisição à API
    response = requests.get(api_url, headers=headers)
    result = response.json()
    
    # Obter as estatísticas de análise (malicioso, seguro, etc.)
    analysis_stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    
    # Tratar o caso em que os dados estão ausentes ou incompletos
    malicious_votes = analysis_stats.get("malicious", 0)
    
    # Verificar se o número de votos maliciosos é maior que 0
    if malicious_votes > 0:
        return "URL Testada: Status Maliciosa"
    return "URL Testada: Status Seguro!"

# Função para gerar o relatório
from flask import Response

def generate_report(url, https_result, headers_result):
    report = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Relatório de Segurança para {url}</title>
    </head>
    <body style="font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; color: #333;">
    <div style="text-align: center; width: 90%; max-width: 800px; margin: auto;">
        <header>
            <h1 style="font-size: 2.5rem; margin-bottom: 2rem; color: #1d1e22;">Relatório de Segurança para {url}</h1>
        </header>
        <div style="background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 2rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); text-align: center; margin-bottom: 2rem;">
            <h2 style="font-size: 1.5rem; margin-bottom: 1rem; color: #1d1e22;">Verificação HTTPS:</h2>
            <p>{https_result}</p>
        </div>
        <div style="background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 2rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); text-align: center; margin-bottom: 2rem;">
            <h2 style="font-size: 1.5rem; margin-bottom: 1rem; color: #1d1e22;">Verificação de Headers de Segurança:</h2>
            <ul>
            {"".join(f"<li>{header}</li>" for header in headers_result)}
            </ul>
        </div>
        <div style="display: flex; justify-content: center; align-items: center; gap: 20px;">
            <a href="/" style="padding: 0.7rem 1.5rem; font-size: 1rem; border: none; border-radius: 4px; background-color: #4285f4; color: white; text-decoration: none; display: inline-block; transition: background-color 0.3s;">
                Realizar Outra Consulta
            </a>
        </div>
    </div>
    </body>
    </html>
    """
    return Response(report, content_type='text/html')


# Rota para a página principal
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        https_result = check_https(url)
        headers_result = check_security_headers(url)
        return generate_report(url, https_result, headers_result)
    return render_template('index.html')


# Nova rota para verificação de URL maliciosa
@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form['malicious_url']
    google_api_key = os.getenv('GOOGLE_API_KEY') # Substitua por sua chave de API
    virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')  # Substitua por sua chave de API

    google_result = check_google_safe_browsing(google_api_key, url)
    virustotal_result = check_virustotal(virustotal_api_key, url)

    return render_template('resultMaliciosa.html', url=url, google_result=google_result, virustotal_result=virustotal_result)

# Rota para acessar os relatórios
@app.route('/static/reports/<report_file>')
def report(report_file):
    return send_from_directory('static/reports', report_file)

if __name__ == "__main__":
    app.run(debug=True)
