from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from http.client import HTTPSConnection
from urlextract import URLExtract
from urllib.parse import urlparse
import ipaddress
import re
import requests
import ssl
import tldextract
import whois
import urllib
import urllib.request

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-VARIABLES GLOBALES=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#


LEGITIMATE = -1
PHISHING = 1
SUSPICIOUS = 0
ERROR = 2
STATUS_ERROR = 500
STATUS_OK = 200


shorteningServiceList = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                        r"tr\.im|link\.zip\.net|xini\.eu|tad\.ly|cut\.ly"

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-EXTRACIÓN DE CARACTERÍSTICAS MAIN-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#

response = {}
url_shorter = ""


def getfeatures(url):
    global url_shorter, response
    response = {}
    response['errors'] = []
    result = ifresponse(url)
    result_whois = whois_request(url)
    if result == ERROR:
        return response
    url = response['url']
    response['features'] = [None for _ in range(23)]
    response['features'][0] = having_ip_address(url)
    response['features'][1] = length_of_url(url)
    response['features'][2] = shortening_services(
        url) if url_shorter == "" else shortening_services(url_shorter)
    response['features'][3] = having_at_symbol(url)
    response['features'][4] = double_slash_redirection(url)
    response['features'][5] = prefix_suffix(url)
    response['features'][6] = sub_domains(url)
    response['features'][7] = ssl_state(url)
    response['features'][8] = registrationDominion(result_whois)
    response['features'][9] = faviconVerificacion(result, url)
    response['features'][10] = HTTPSindominio(url)
    response['features'][11] = urlofSolicitud(result, url)
    response['features'][12] = urlanchor(result, url)
    response['features'][13] = enlacesMetaScriptLink(result, url)
    response['features'][14] = SFHdirection(result, url)
    response['features'][15] = SFHdirectionmail(result)
    response['features'][16] = anormalUrl(result_whois, url)
    response['features'][17] = iframeredirection(result)
    response['features'][18] = on_mouse_over(result)
    response['features'][19] = right_click(result)
    response['features'][20] = domain_age(result_whois)
    response['features'][21] = web_traffic(url)
    response['features'][22] = dns_record(result_whois)

    response['status'] = STATUS_OK

    response['result'] = 0.20
    return response


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-CONDICIONANTES=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#


def ifresponse(url):
    if is_shortening(url) or url[:4] != "http":
        url = "http://"+url
    r = conection(url)
    if (r == ERROR):
        url = url.replace("http://", "https://")
        r = conection(url)
        if (r == ERROR):
            response['url'] = url
            response['status'] = STATUS_ERROR
            response['errors'].append("URL no válida o sitio web caído")
            return ERROR
    response['url'] = r.url
    return r


def is_shortening(url):
    global url_shorter, shorteningServiceList
    url_shorter = url
    match = re.search(shorteningServiceList, url)
    return match


def whois_request(url):
    host = urlparse(url).netloc
    if host == "" or host == None:
        return ERROR
    try:
        dominio = whois.whois(host)
        return dominio
    except:
        response['errors'].append("Informacion sobre el dominio no accesible")
        return ERROR


def conection(url):
    try:
        r = requests.get(url, timeout=2)
    except:
        try:
            r = requests.get(url, verify=False, timeout=2)
        except:
            return ERROR
    return r

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-EXTRACCION DE CARACTERÍSTICAS-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-#

# 1


def having_ip_address(url):
    host = urlparse(url).netloc
    if "0x" in host and "." in host:
        temp = host.split(".")
        host_ = ""
        for part in temp:
            try:
                x = str(int(part, 16))
            except:
                x = part
            host_ += x+"."
        host_ = host_[:-1]
    else:
        host_ = host
    try:
        ipaddress.ip_address(host_)
        return PHISHING
    except:
        return LEGITIMATE

# 2


def length_of_url(url):
    if len(url) < 54:
        return LEGITIMATE
    elif len(url) >= 54 and len(url) <= 72:
        return SUSPICIOUS
    else:
        return PHISHING

# 3


def shortening_services(url):
    match = re.search(shorteningServiceList, url)
    if match:
        return PHISHING
    else:
        return LEGITIMATE

# 4


def having_at_symbol(url):
    if "@" in url:
        return PHISHING
    else:
        return LEGITIMATE

# 5


def double_slash_redirection(url):
    path = urlparse(url).path
    if "//" in path:
        return PHISHING
    else:
        return LEGITIMATE

# 6


def prefix_suffix(url):
    if '-' in urlparse(url).netloc:
        return PHISHING
    else:
        return LEGITIMATE

# 7


def sub_domains(url):
    subdomains = tldextract.extract(url).subdomain
    if subdomains.count(".") == 0:
        return LEGITIMATE
    elif subdomains.count(".") == 1:
        return SUSPICIOUS
    else:
        return PHISHING

# 8


class CustomHTTPSConnection(HTTPSConnection, object):
    def connect(self):
        super(CustomHTTPSConnection, self).connect()
        certificado = self.sock.getpeercert()
        return certificado


def getcertificate(host):
    global response
    context = ssl.create_default_context()
    context.check_hostname = False
    try:
        certificado = CustomHTTPSConnection(
            host=host, context=context).connect()
    except:
        response['errors'].append("Certificado SSL no accesible")
        return PHISHING
    fecha_contrato = datetime.strptime(
        certificado['notBefore'], '%b %d %H:%M:%S %Y %Z')
    fecha_vencimiento = datetime.strptime(
        certificado['notAfter'], '%b %d %H:%M:%S %Y %Z')
    diferencia = (fecha_vencimiento-fecha_contrato)/timedelta(days=365)
    if diferencia >= 0.98:
        return LEGITIMATE
    else:
        return PHISHING


def ssl_state(url):
    host = urlparse(url).netloc
    if urlparse(url).scheme != "https":
        return PHISHING
    else:
        return getcertificate(host)

# 9


def registrationDominion(dominio):
    global response
    if dominio == ERROR:
        return PHISHING
    try:
        if type(dominio.expiration_date) == list:
            expiration_date = dominio.expiration_date[0]
        else:
            expiration_date = dominio.expiration_date
        if type(dominio.updated_date) == list:
            updated_date = dominio.updated_date[0]
        else:
            updated_date = dominio.updated_date
        tiempo_restante = (expiration_date - updated_date)
    except:
        response['errors'].append(
            "Información insuficiente del dominio-registration")
        return PHISHING

    if tiempo_restante.days/365 < 0.98:
        return PHISHING
    else:
        return LEGITIMATE

# 10


def faviconVerificacion(r, url):
    soup = BeautifulSoup(r.text, 'html.parser')
    favicon = None
    for item in soup.find_all('link'):
        if item.get('rel') != None:
            if "icon" in item.get('rel'):
                favicon = item
    if favicon != None:
        href = favicon.get('href')
        host = urlparse(href).netloc if urlparse(
            href).netloc != "" else urlparse(url).netloc
        if host == urlparse(url).netloc:
            return LEGITIMATE
        else:
            return PHISHING
    else:
        return PHISHING

# 11

# 12


def HTTPSindominio(url):
    if 'http' in urlparse(url).netloc:
        return PHISHING
    else:
        return LEGITIMATE

# 13


def urlofSolicitud(r, url):
    soup = BeautifulSoup(r.text, 'html.parser')
    objects = soup.find_all('audio', src=True)+soup.find_all('img', src=True) + \
        soup.find_all('video', src=True)
    if len(objects) == 0:
        return LEGITIMATE
    count = 0
    for item in objects:
        src = item.get('src')
        host = urlparse(src).netloc if urlparse(
            src).netloc != "" else urlparse(url).netloc
        if host != urlparse(url).netloc:
            count += 1
    porcentaje = round((count*100)/len(objects), 2)
    if porcentaje < 22:
        return LEGITIMATE
    elif porcentaje >= 22 and porcentaje <= 61:
        return SUSPICIOUS
    else:
        return PHISHING

# 14


def urlanchor(r, url):
    soup = BeautifulSoup(r.text, 'html.parser')
    objects = soup.find_all('a', href=True)
    if len(objects) == 0:
        return LEGITIMATE
    count = 0
    for item in objects:
        if item.get('href') == None or item.get('href') == "":
            count += 1
            continue
        href = item.get('href').replace(" ", "")
        if "javascript:void" in href or href[0] == "#":
            count += 1
            continue
        host = urlparse(href).netloc if urlparse(
            href).netloc != "" else urlparse(href).netloc
        if host != urlparse(url).netloc:
            count += 1
    porcentaje = round((count*100)/len(objects), 2)
    if porcentaje < 31:
        return LEGITIMATE
    elif porcentaje >= 31 and porcentaje <= 67:
        return SUSPICIOUS
    else:
        return PHISHING

# 15


def enlacesMetaScriptLink(r, url):
    soup = BeautifulSoup(r.text, 'html.parser')
    objects = soup.find_all('meta', content=True)+soup.find_all('link', href=True) + \
        soup.find_all('script', src=True)
    if len(objects) == 0:
        return LEGITIMATE
    count = 0
    count2 = 0
    for item in objects:
        src = ""
        extractor = URLExtract()
        if item.get('content') != None:
            aux = extractor.find_urls(item.get('content'))
            if aux == []:
                count2 += 1
                continue
            else:
                src = aux[0]
        elif item.get('href') != None:
            src = item.get('href')
        elif item.get('src') != None:
            src = item.get('src')
        else:
            count2 += 1
            continue
        host = urlparse(src).netloc if urlparse(
            src).netloc != "" else urlparse(url).netloc
        if host != urlparse(url).netloc:
            count += 1
    if len(objects)-count2 == 0:
        return LEGITIMATE
    porcentaje = round((count*100)/(len(objects)-count2), 2)
    if porcentaje < 22:
        return LEGITIMATE
    elif porcentaje >= 22 and porcentaje <= 61:
        return SUSPICIOUS
    else:
        return PHISHING

# 16


def SFHdirection(r, url):
    soup = BeautifulSoup(r.text, 'html.parser')
    form = soup.form
    if form == None:
        return LEGITIMATE
    elif form.get('action') == None:
        return PHISHING
    elif form.get('action') == "":
        return PHISHING
    elif "about:blank" in form.get('action').replace(" ", ""):
        return PHISHING
    else:
        href = form.get('action').replace(" ", "")
        host = urlparse(href).netloc if urlparse(
            href).netloc != "" else urlparse(url).netloc
        if host != urlparse(url).netloc:
            return SUSPICIOUS
        else:
            return LEGITIMATE

# 17


def SFHdirectionmail(r):
    soup = BeautifulSoup(r.text, 'html.parser')
    form = soup.form
    if form == None:
        return LEGITIMATE
    elif form.get('action') == None:
        return LEGITIMATE
    elif form.get('action') == "":
        return LEGITIMATE
    elif "mailto" in form.get('action'):
        return PHISHING
    else:
        return LEGITIMATE

# 18


def anormalUrl(dominio, url):
    host = urlparse(url).netloc
    if dominio == ERROR:
        return PHISHING
    try:
        if type(dominio.domain_name) == list:
            for item in dominio.domain_name:
                if item.lower() in host.lower():
                    return LEGITIMATE
        else:
            if dominio.domain_name.lower() in host.lower():
                return LEGITIMATE
            else:
                return PHISHING
        return PHISHING
    except:
        response['errors'].append(
            "Información insuficiente del dominio-anormal")
        return PHISHING

# 19


def iframeredirection(r):
    soup = BeautifulSoup(r.text, 'html.parser')
    iframes = soup.find_all('iframe', frameborder=True)
    if iframes == []:
        return LEGITIMATE
    return PHISHING

# 20


def on_mouse_over(r):
    if re.findall("<script>.+onmouseover.+</script>", r.text):
        return PHISHING
    else:
        return LEGITIMATE

# 21


def right_click(r):
    if re.findall(r"event.button ?== ?2", r.text):
        return PHISHING
    else:
        return LEGITIMATE

# 22


def domain_age(dominio):
    if dominio == ERROR:
        return PHISHING
    try:
        if type(dominio.expiration_date) == list:
            expiration_date = dominio.expiration_date[0]
        else:
            expiration_date = dominio.expiration_date
        if type(dominio.creation_date) == list:
            creation_date = dominio.creation_date[0]
        else:
            creation_date = dominio.creation_date
        tiempo_restante = (expiration_date - creation_date)
    except:
        response['errors'].append("Información insuficiente del dominio")
        return PHISHING

    if tiempo_restante.days/30 < 6:
        return PHISHING
    else:
        return LEGITIMATE

# 23


def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except:
        return PHISHING
    if rank < 100000:
        return LEGITIMATE
    if rank > 100000:
        return SUSPICIOUS
    else:
        return PHISHING

# 24


def dns_record(dominio):
    if dominio == ERROR:
        return PHISHING
    try:
        dns = dominio.dnssec
        if dns == None:
            return PHISHING
        else:
            return LEGITIMATE
    except:
        response['errors'].append("Información insuficiente del dominio")
        return PHISHING
