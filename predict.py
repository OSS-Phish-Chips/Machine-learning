# app.py
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
from urllib.parse import urlparse
import re
import math

app = FastAPI()

# CORS (확장/로컬에서 접근 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 필요시 좁혀도 됨
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ✔️ 필요 모듈 불러오기
import re
import socket
import time
import urllib.request
import requests
import warnings
import whois
import pandas as pd
from bs4 import BeautifulSoup
from datetime import datetime
from googlesearch import search
from patterns import *
import urllib3
import random
from urllib.parse import urlparse

from tqdm import tqdm
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# SSL 경고 비활성화
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Path of your local server. Different for different OSs.
LOCALHOST_PATH = "/Library/WebServer/Documents/"
DIRECTORY_NAME = "Malicious-Web-Content-Detection-Using-Machine-Learning"

# ============================================================================
# 🔧 개선된 유틸리티 함수들
# ============================================================================

# ===== Patch: robust DNS check (IPv4/IPv6) =====
def robust_dns_check(hostname: str) -> bool:
    try:
        # IPv4/IPv6 모두 조회
        infos = socket.getaddrinfo(hostname, None)
        return len(infos) > 0
    except socket.gaierror:
        # 'www.' 제거 재시도
        if hostname.startswith('www.'):
            try:
                return len(socket.getaddrinfo(hostname[4:], None)) > 0
            except socket.gaierror:
                return False
        return False

def safe_url_request_improved(url, max_retries=2, timeout=10):
    """개선된 안전한 URL 요청 처리"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    
    # URL 전처리
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    for attempt in range(max_retries + 1):
        try:
            if attempt > 0:
                time.sleep(random.uniform(0.5, 2))
            
            response = requests.get(
                url, 
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                stream=True
            )
            
            response.raise_for_status()
            
            # 콘텐츠 크기 제한
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > 5 * 1024 * 1024:  # 5MB 제한
                return None, None
            
            soup = BeautifulSoup(response.content, 'html.parser')
            return response, soup
            
        except (requests.exceptions.SSLError, 
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects) as e:
            if attempt == max_retries:
                return None, None
            continue
        except Exception:
            return None, None
    
    return None, None

# ===== Patch: whois (두 패키지 모두 호환) =====
def safe_whois_query(hostname):
    """
    - pip install whois  (whois.query)
    - 또는 pip install python-whois (whois.whois)
    둘 중 무엇이 깔려 있어도 동작하도록 처리.
    """
    try:
        # 시나리오 1: whois.query API
        q = getattr(whois, 'query', None)
        if callable(q):
            domain = q(hostname)
            if domain:
                return domain
    except Exception:
        pass

    try:
        # 시나리오 2: whois.whois API (dict-like)
        w = getattr(whois, 'whois', None)
        if callable(w):
            data = w(hostname)
            class _Domain:
                def __init__(self, d):
                    self.name = d.get('domain_name')
                    self.creation_date = d.get('creation_date')
                    self.expiration_date = d.get('expiration_date')
            return _Domain(data) if data else None
    except Exception:
        pass

    # 'www.' 제거 재시도
    if hostname.startswith('www.'):
        return safe_whois_query(hostname[4:])

    return None

# ============================================================================
# 🎯 기존 특징 추출 함수들 (그대로 유지)
# ============================================================================

def having_ip_address(url):
    ipv4_pattern = r'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]))'
    ipv6_pattern = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1

def url_length(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1

def shortening_service(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                         r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                         r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                         r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|" \
                         r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|" \
                         r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|" \
                         r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                         r"tr\.im|link\.zip\.net"
    match = re.search(shortening_services, url)
    return -1 if match else 1

def having_at_symbol(url):
    match = re.search('@', url)
    return -1 if match else 1

def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1

def prefix_suffix(domain):
    match = re.search('-', domain)
    return -1 if match else 1

def having_sub_domain(url):
    if having_ip_address(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1

def domain_registration_length(domain):
    try:
        expiration_date = domain.expiration_date
        today = datetime.now()
        
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            registration_length = abs((expiration_date - today).days)
            return 1 if registration_length / 365 > 1 else -1
    except:
        pass
    return 0  # 중립값


# ===== Patch: favicon (조기 반환 제거, 정확도 개선) =====
def favicon(wiki, soup, domain):
    if not soup:
        return 0
    try:
        links = soup.find_all('link', href=True)
        if not links:
            return 1
        safe_cnt, total = 0, 0
        for link in links:
            href = link.get('href', '').strip()
            if not href:
                continue
            total += 1
            # 절대/상대 URL normalize
            if href.startswith('//'):
                href_host = get_hostname_from_url('http:' + href)
            elif href.startswith(('http://', 'https://')):
                href_host = get_hostname_from_url(href)
            else:
                href_host = domain  # 상대경로면 same-origin 취급
            if domain in href_host or (wiki and get_hostname_from_url(wiki) in href):
                safe_cnt += 1
        if total == 0:
            return 1
        ratio = safe_cnt / total * 100
        return 1 if ratio >= 50 else (0 if ratio >= 20 else -1)
    except Exception:
        return 1

def https_token(url):
    http_https = r'https://|http://'
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return -1 if match else 1

def request_url(wiki, soup, domain):
    if not soup:
        return 0
    try:
        i = 0
        success = 0
        
        for tag_name in ['img', 'audio', 'embed', 'iframe']:
            for tag in soup.find_all(tag_name, src=True):
                src = tag.get('src', '')
                dots = [x.start() for x in re.finditer(r'\.', src)]
                if wiki in src or domain in src or len(dots) == 1:
                    success += 1
                i += 1
        
        if i == 0:
            return 1
            
        percentage = success / float(i) * 100
        if percentage < 22.0:
            return 1
        elif 22.0 <= percentage < 61.0:
            return 0
        else:
            return -1
    except:
        return 1

def url_of_anchor(wiki, soup, domain):
    if not soup:
        return 0
    try:
        i = 0
        unsafe = 0
        for a in soup.find_all('a', href=True):
            href = a.get('href', '')
            if "#" in href or "javascript" in href.lower() or "mailto" in href.lower() or not (
                    wiki in href or domain in href):
                unsafe += 1
            i += 1
        
        if i == 0:
            return 1
            
        percentage = unsafe / float(i) * 100
        if percentage < 31.0:
            return 1
        elif 31.0 <= percentage < 67.0:
            return 0
        else:
            return -1
    except:
        return 1

def links_in_tags(wiki, soup, domain):
    if not soup:
        return 0
    try:
        i = 0
        success = 0
        
        for link in soup.find_all('link', href=True):
            href = link.get('href', '')
            dots = [x.start() for x in re.finditer(r'\.', href)]
            if wiki in href or domain in href or len(dots) == 1:
                success += 1
            i += 1

        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            dots = [x.start() for x in re.finditer(r'\.', src)]
            if wiki in src or domain in src or len(dots) == 1:
                success += 1
            i += 1
        
        if i == 0:
            return 1
            
        percentage = success / float(i) * 100
        if percentage < 17.0:
            return 1
        elif 17.0 <= percentage < 81.0:
            return 0
        else:
            return -1
    except:
        return 1

# ===== Patch: sfh (여러 form 종합 판단) =====
def sfh(wiki, soup, domain):
    if not soup:
        return 1
    try:
        forms = soup.find_all('form', action=True)
        if not forms:
            return 1
        neg, mid, pos = 0, 0, 0
        for form in forms:
            action = (form.get('action') or '').strip().lower()
            if action in ("", "about:blank"):
                neg += 1
            elif (domain and domain.lower() in action) or (wiki and get_hostname_from_url(wiki).lower() in action):
                pos += 1
            else:
                mid += 1
        # 다수결
        if neg > max(mid, pos):
            return -1
        if mid >= pos:
            return 0
        return 1
    except Exception:
        return 1

def submitting_to_email(soup):
    if not soup:
        return 1
    try:
        for form in soup.find_all('form', action=True):
            action = form.get('action', '')
            if "mailto:" in action:
                return -1
    except:
        pass
    return 1

def abnormal_url(domain, url):
    try:
        if domain and hasattr(domain, 'name') and domain.name:
            hostname = domain.name
            match = re.search(hostname, url)
            return 1 if match else -1
    except:
        pass
    return 0

def i_frame(soup):
    if not soup:
        return 1
    try:
        for iframe in soup.find_all(['iframe', 'i_frame'], width=True, height=True):
            width = iframe.get('width', '')
            height = iframe.get('height', '')
            frameborder = iframe.get('frameBorder', iframe.get('frameborder', ''))
            
            if width == "0" and height == "0" and frameborder == "0":
                return -1
            if width == "0" or height == "0" or frameborder == "0":
                return 0
    except:
        pass
    return 1

def age_of_domain(domain):
    try:
        if domain and hasattr(domain, 'creation_date') and domain.creation_date:
            creation_date = domain.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            today = datetime.now()
            age_days = abs((today - creation_date).days)
            return 1 if age_days / 30 >= 6 else -1
    except:
        pass
    return 0

def web_traffic_alternative(url):
    """Alexa 대신 다른 방법으로 트래픽 추정"""
    try:
        # 간단한 휴리스틱: 도메인 길이와 구조로 판단
        hostname = get_hostname_from_url(url)
        
        # 유명한 도메인들 (간단한 화이트리스트)
        popular_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'amazon.com', 'microsoft.com', 'apple.com'
        ]
        
        for domain in popular_domains:
            if domain in hostname.lower():
                return 1
        
        # 도메인 구조 기반 점수
        if len(hostname.split('.')) <= 2 and len(hostname) < 15:
            return 1
        elif len(hostname) > 30 or len(hostname.split('.')) > 4:
            return -1
        else:
            return 0
    except:
        return 0

# ===== Patch: google index (패키지 차이 흡수 + 빠른 실패) =====
def google_index_safe(url):
    """
    googlesearch 패키지 군의 파라미터 차이를 흡수.
    실패/차단 시 0 반환.
    """
    try:
        time.sleep(random.uniform(0.3, 0.8))  # rate-limit 배려(짧게)
        query = f"site:{get_hostname_from_url(url)}"
        # 우선 기본 시그니처
        try:
            results = list(search(query, num_results=3))
            return 1 if results else -1
        except TypeError:
            # 대체 시그니처 (다른 패키지)
            results = list(search(query, num=3, stop=3, pause=0.5))
            return 1 if results else -1
    except Exception:
        return 0

def statistical_report(url, hostname):
    """통계 리포트 (IP 기반)"""
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        return 0  # DNS 실패 시 중립값
    
    # 알려진 악성 도메인/IP 패턴
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    
    if url_match or ip_match:
        return -1
    else:
        return 1

def get_hostname_from_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # scheme 보정
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split('/')[0]
    # strip 'www.'
    if host.lower().startswith('www.'):
        host = host[4:]
    return host

# ============================================================================
# 🚀 개선된 메인 함수 (단계별 fallback 적용)
# ============================================================================

def extract_features_with_fallback(url):
    """
    단계별 fallback이 적용된 특징 추출 함수
    """
    status = []
    hostname = get_hostname_from_url(url)
    
    # === 1단계: URL 기반 특징 (항상 추출 가능) ===
    try:
        status.extend([
            having_ip_address(url),          # F1
            url_length(url),                 # F2  
            shortening_service(url),         # F3
            having_at_symbol(url),           # F4
            double_slash_redirecting(url),   # F5
            prefix_suffix(hostname),         # F6
            having_sub_domain(url),          # F7
        ])
    except Exception as e:
        print(f"URL 특징 추출 오류: {e}")
        status.extend([0] * 7)
    
    # === 2단계: DNS 해석 및 whois 조회 ===
    dns_available = robust_dns_check(hostname)
    domain = None
    
    if dns_available:
        domain = safe_whois_query(hostname)
        dns_status = 1 if domain else 0
    else:
        dns_status = -1
    
    # 도메인 등록 기간
    try:
        if domain:
            status.append(domain_registration_length(domain))  # F8
        else:
            status.append(0 if dns_available else -1)
    except:
        status.append(0)
    
    # === 3단계: HTTP 요청 및 HTML 파싱 ===
    if dns_available:
        response, soup = safe_url_request_improved(url)
        http_available = (response is not None and soup is not None)
    else:
        response, soup = None, None
        http_available = False
    
    # HTML 기반 특징들
    try:
        if http_available:
            status.extend([
                favicon(url, soup, hostname),           # F9
                https_token(url),                       # F10
                request_url(url, soup, hostname),       # F11
                url_of_anchor(url, soup, hostname),     # F12
                links_in_tags(url, soup, hostname),     # F13
                sfh(url, soup, hostname),               # F14
                submitting_to_email(soup),              # F15
            ])
        else:
            # HTTP 실패 시 URL 기반으로만 판단 가능한 것들
            status.extend([
                0,                           # F9 - favicon (중립)
                https_token(url),           # F10 - https_token (URL만으로 판단 가능)
                0,                          # F11 - request_url (중립)
                0,                          # F12 - url_of_anchor (중립)
                0,                          # F13 - links_in_tags (중립)
                1,                          # F14 - sfh (기본값: 안전)
                1,                          # F15 - submitting_to_email (기본값: 안전)
            ])
    except Exception as e:
        print(f"HTML 특징 추출 오류: {e}")
        status.extend([0] * 7)
    
    # === 4단계: 도메인 기반 특징들 ===
    try:
        if domain:
            status.extend([
                abnormal_url(domain, url),    # F16
                i_frame(soup),                # F17
                age_of_domain(domain),        # F18
            ])
        else:
            status.extend([
                0 if dns_available else -1,  # F16
                i_frame(soup) if http_available else 1,  # F17
                0 if dns_available else -1,  # F18
            ])
    except:
        status.extend([0, 1, 0])
    
    # === 5단계: 외부 서비스 의존 특징들 ===
    status.append(dns_status)                    # F19 - DNS
    status.append(web_traffic_alternative(url))  # F20 - 웹 트래픽 (대체 방법)
    
    # Google 인덱스 (rate limiting 고려)
    try:
        status.append(google_index_safe(url))    # F21
    except:
        status.append(0)
    
    # 통계 리포트
    try:
        status.append(statistical_report(url, hostname))  # F22
    except:
        status.append(0)
    
    return status

# ============================================================================
# 🔄 배치 처리 함수 (개선됨)
# ============================================================================

def extract_features_batch_robust(urls, batch_size=25):
    """
    견고한 배치 처리 - 더 작은 배치와 더 많은 휴식
    """
    features_list = []
    failed_urls = []
    
    for i in range(0, len(urls), batch_size):
        batch_urls = urls[i:i+batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(urls)-1)//batch_size + 1
        
        print(f"📦 배치 {batch_num}/{total_batches} 처리 중 ({len(batch_urls)}개 URL)...")
        
        batch_features = []
        for j, url in enumerate(tqdm(batch_urls, desc=f"배치 {batch_num}")):
            try:
                features = extract_features_with_fallback(url)
                batch_features.append(features)
                
                # URL 간 휴식 (서버 부하 방지)
                if j < len(batch_urls) - 1:
                    time.sleep(random.uniform(0.1, 0.5))
                    
            except Exception as e:
                print(f"💥 URL 처리 실패: {url[:50]}... - {str(e)[:100]}")
                batch_features.append([0] * 22)  # 중립값으로 설정
                failed_urls.append(url)
        
        features_list.extend(batch_features)
        
        # 배치 간 휴식
        if i + batch_size < len(urls):
            sleep_time = random.uniform(2, 5)
            print(f"💤 {sleep_time:.1f}초 휴식...")
            time.sleep(sleep_time)
    
    print(f"✅ 처리 완료! 실패한 URL: {len(failed_urls)}개")
    if failed_urls:
        print("실패 URL 샘플:", failed_urls[:5])
    
    return features_list

# ============================================================================
# 📊 CSV 처리 함수 (그대로 유지)
# ============================================================================

def extract_features_from_csv(csv_path, url_column, label_column=None):
    """CSV에서 URL 로드 + 특징 추출"""
    df = pd.read_csv(csv_path, encoding="latin1") 
    features_list = []
    labels = []

    print(f"📄 CSV 로드 완료: {len(df)}개 URL")
    
    for _, row in tqdm(df.iterrows(), total=len(df), desc="특징 추출"):
        url = row[url_column]
        try:
            features = extract_features_with_fallback(url)
        except Exception as e:
            print(f"행 처리 오류: {e}")
            features = [0] * 22
        features_list.append(features)

        if label_column:
            labels.append(row[label_column])

    feature_df = pd.DataFrame(features_list, columns=[f"F{i}" for i in range(1, 23)])

    if label_column:
        feature_df["label"] = labels

    return feature_df


# 1) 모델 로드
MODEL_PATH = "random_forest_model_5000.pkl"
model = joblib.load(MODEL_PATH)

# 2) 완성된 extract_features 함수
def extract_features(url: str):
    """
    22개 특징을 추출하는 함수 - 기존 extract_features_with_fallback을 사용
    """
    return extract_features_with_fallback(url)

class PredictResponse(BaseModel):
    label: int
    proba: float
    features: dict

@app.get("/predict", response_model=PredictResponse)
def predict(url: str = Query(..., description="http(s)://로 시작하는 URL")):
    feats = extract_features(url)
    
    # 22개 특징이 모두 추출되었는지 확인
    if len(feats) != 22:
        feats = feats + [0] * (22 - len(feats))  # 부족한 특징은 0으로 채움
    
    # 모델 입력 차원에 맞추기
    X = [feats]
    
    # 분류/확률
    try:
        proba = float(model.predict_proba(X)[0][1])
    except Exception:
        # 모델이 predict_proba 없으면 예외 → 대신 predict만
        proba = float(model.predict(X)[0])

    label = 1 if proba >= 0.5 else 0
    
    # 특징들을 의미있는 이름으로 매핑
    feature_names = [
        "having_ip_address", "url_length", "shortening_service", "having_at_symbol",
        "double_slash_redirecting", "prefix_suffix", "having_sub_domain", 
        "domain_registration_length", "favicon", "https_token", "request_url",
        "url_of_anchor", "links_in_tags", "sfh", "submitting_to_email",
        "abnormal_url", "i_frame", "age_of_domain", "dns_record", "web_traffic",
        "google_index", "statistical_report"
    ]
    
    features_dict = {name: feats[i] for i, name in enumerate(feature_names)}
    
    return PredictResponse(
        label=label,
        proba=proba,
        features=features_dict
    )

# 추가 엔드포인트: 배치 예측
@app.post("/predict_batch")
def predict_batch(urls: list[str]):
    """여러 URL에 대한 배치 예측"""
    results = []
    
    for url in urls:
        try:
            feats = extract_features(url)
            if len(feats) != 22:
                feats = feats + [0] * (22 - len(feats))
            
            X = [feats]
            try:
                proba = float(model.predict_proba(X)[0][1])
            except:
                proba = float(model.predict(X)[0])
            
            label = 1 if proba >= 0.5 else 0
            
            results.append({
                "url": url,
                "label": label,
                "proba": proba
            })
        except Exception as e:
            results.append({
                "url": url,
                "label": -1,  # 오류 표시
                "proba": 0.0,
                "error": str(e)
            })
    
    return {"results": results}

# 헬스체크 엔드포인트
@app.get("/health")
def health_check():
    return {"status": "healthy", "model_loaded": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
