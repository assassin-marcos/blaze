"""
Blaze Technology Detector - Fingerprint web server technology stack.
Detects web servers, languages, frameworks, CMS, and more through
header analysis, cookie inspection, HTML parsing, and active probing.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set


@dataclass
class TechResult:
    technologies: Dict[str, float] = field(default_factory=dict)
    server: str = ""
    language: str = ""
    framework: str = ""
    cms: str = ""
    os: str = ""
    details: List[str] = field(default_factory=list)

    def add_technology(self, name: str, confidence: float):
        self.technologies[name] = max(
            self.technologies.get(name, 0), confidence
        )

    @property
    def detected_names(self) -> List[str]:
        return sorted(
            self.technologies.keys(),
            key=lambda k: self.technologies[k],
            reverse=True,
        )


# ─────────────────────── Header-Based Signatures ───────────────────────

SERVER_SIGNATURES = {
    r"(?i)apache": ("Apache", "server"),
    r"(?i)nginx": ("Nginx", "server"),
    r"(?i)microsoft-iis": ("IIS", "server"),
    r"(?i)litespeed": ("LiteSpeed", "server"),
    r"(?i)openresty": ("OpenResty/Nginx", "server"),
    r"(?i)caddy": ("Caddy", "server"),
    r"(?i)gunicorn": ("Gunicorn/Python", "server"),
    r"(?i)uvicorn": ("Uvicorn/Python", "server"),
    r"(?i)daphne": ("Daphne/Python", "server"),
    r"(?i)waitress": ("Waitress/Python", "server"),
    r"(?i)werkzeug": ("Werkzeug/Python", "server"),
    r"(?i)tornado": ("Tornado/Python", "server"),
    r"(?i)jetty": ("Jetty/Java", "server"),
    r"(?i)tomcat": ("Tomcat/Java", "server"),
    r"(?i)wildfly": ("WildFly/Java", "server"),
    r"(?i)express": ("Express/Node.js", "server"),
    r"(?i)kestrel": ("Kestrel/.NET", "server"),
    r"(?i)cowboy": ("Cowboy/Erlang", "server"),
    r"(?i)puma": ("Puma/Ruby", "server"),
    r"(?i)unicorn": ("Unicorn/Ruby", "server"),
    r"(?i)phusion.passenger": ("Passenger/Ruby", "server"),
    r"(?i)thin": ("Thin/Ruby", "server"),
}

POWERED_BY_SIGNATURES = {
    r"(?i)php": ("PHP", "language"),
    r"(?i)asp\.net": ("ASP.NET", "language"),
    r"(?i)express": ("Express/Node.js", "framework"),
    r"(?i)next\.?js": ("Next.js", "framework"),
    r"(?i)nuxt": ("Nuxt.js", "framework"),
    r"(?i)django": ("Django", "framework"),
    r"(?i)flask": ("Flask", "framework"),
    r"(?i)rails": ("Ruby on Rails", "framework"),
    r"(?i)laravel": ("Laravel", "framework"),
    r"(?i)symfony": ("Symfony", "framework"),
    r"(?i)codeigniter": ("CodeIgniter", "framework"),
    r"(?i)cakephp": ("CakePHP", "framework"),
    r"(?i)spring": ("Spring/Java", "framework"),
    r"(?i)struts": ("Struts/Java", "framework"),
    r"(?i)servlet": ("Java Servlet", "framework"),
    r"(?i)perl": ("Perl", "language"),
    r"(?i)pleskwin|plesk": ("Plesk", "server"),
}

# ────────────────────── Cookie-Based Detection ──────────────────────

COOKIE_SIGNATURES = {
    r"PHPSESSID": ("PHP", 0.9),
    r"JSESSIONID": ("Java", 0.9),
    r"ASP\.NET_SessionId": ("ASP.NET", 0.9),
    r"ASPSESSIONID": ("ASP Classic", 0.9),
    r"connect\.sid": ("Express/Node.js", 0.7),
    r"laravel_session": ("Laravel", 0.95),
    r"_rails_session": ("Ruby on Rails", 0.9),
    r"rack\.session": ("Ruby/Rack", 0.8),
    r"ci_session": ("CodeIgniter", 0.9),
    r"csrftoken": ("Django", 0.6),
    r"django_language": ("Django", 0.8),
    r"sessionid": ("Django", 0.4),
    r"flask": ("Flask", 0.5),
    r"XSRF-TOKEN": ("Laravel/Angular", 0.5),
    r"symfony": ("Symfony", 0.8),
    r"CAKEPHP": ("CakePHP", 0.9),
    r"wp-settings": ("WordPress", 0.9),
    r"wordpress_logged_in": ("WordPress", 0.95),
    r"wordpress_test_cookie": ("WordPress", 0.95),
    r"joomla_user_state": ("Joomla", 0.9),
    r"drupal\.visitor": ("Drupal", 0.9),
    r"DotNetNukeAnonymous": ("DotNetNuke", 0.9),
    r"PrestaShop": ("PrestaShop", 0.9),
    r"Shopify": ("Shopify", 0.8),
    r"_shopify_sa_t": ("Shopify", 0.9),
    r"magento": ("Magento", 0.8),
    r"frontend=": ("Magento", 0.5),
    r"MoodleSession": ("Moodle", 0.9),
    r"confluence\.": ("Confluence", 0.7),
    r"JSESSIONID.*confluence": ("Confluence", 0.8),
    r"crowd\.token": ("Confluence", 0.8),
    r"JENKINS_SESSION_ID": ("Jenkins", 0.9),
    r"_gitlab_session": ("GitLab", 0.95),
    r"_sap_": ("SAP", 0.7),
    r"sap-usercontext": ("SAP", 0.9),
}

# ─────────────────────── Body-Based Detection ───────────────────────

BODY_SIGNATURES = {
    r'<meta\s+name=["\']generator["\'][^>]*wordpress': ("WordPress", 0.95),
    r"wp-content/": ("WordPress", 0.85),
    r"wp-includes/": ("WordPress", 0.85),
    r"wp-json": ("WordPress", 0.8),
    r'<meta\s+name=["\']generator["\'][^>]*Joomla': ("Joomla", 0.95),
    r"/media/system/js/": ("Joomla", 0.7),
    r'<meta\s+name=["\']generator["\'][^>]*Drupal': ("Drupal", 0.95),
    r"/sites/default/files/": ("Drupal", 0.8),
    r"/sites/all/": ("Drupal", 0.7),
    r"drupal\.js": ("Drupal", 0.8),
    r"Powered by.*Django": ("Django", 0.7),
    r"csrfmiddlewaretoken": ("Django", 0.8),
    r"__next": ("Next.js", 0.7),
    r"_next/static": ("Next.js", 0.9),
    r"__nuxt": ("Nuxt.js", 0.8),
    r"/_nuxt/": ("Nuxt.js", 0.9),
    r"__NEXT_DATA__": ("Next.js", 0.95),
    r"/static/admin/": ("Django Admin", 0.8),
    r"/rails/": ("Ruby on Rails", 0.6),
    r"data-turbo": ("Ruby on Rails", 0.7),
    r"<script[^>]*react": ("React", 0.6),
    r"<div\s+id=['\"]app['\"]": ("Vue.js/SPA", 0.3),
    r"ng-app|ng-controller": ("Angular", 0.8),
    r"angular\.js|angular\.min\.js": ("AngularJS", 0.9),
    r"ember": ("Ember.js", 0.5),
    r"laravel": ("Laravel", 0.5),
    r"symfony": ("Symfony", 0.4),
    r'<meta\s+name=["\']generator["\'][^>]*shopify': ("Shopify", 0.95),
    r"/cdn\.shopify\.com/": ("Shopify", 0.9),
    r'<meta\s+name=["\']generator["\'][^>]*magento': ("Magento", 0.95),
    r"/skin/frontend/": ("Magento", 0.7),
    r"/static/frontend/": ("Magento 2", 0.7),
    r'<meta\s+name=["\']generator["\'][^>]*ghost': ("Ghost CMS", 0.95),
    r"/ghost/api/": ("Ghost CMS", 0.8),
    r"/typo3/": ("TYPO3", 0.8),
    r"/bitrix/": ("1C-Bitrix", 0.8),
    r"<!-- Start Kentico": ("Kentico", 0.9),
    r"/umbraco/": ("Umbraco", 0.8),
    r"docusaurus": ("Docusaurus", 0.8),
    r"gatsby": ("Gatsby", 0.5),
    r"hugo-": ("Hugo", 0.5),
    r"jekyll": ("Jekyll", 0.5),
    r"pelican": ("Pelican", 0.5),
    # New CMS/Tech signatures
    r"/moodle/": ("Moodle", 0.8),
    r"theme/yui_combo": ("Moodle", 0.7),
    r'<meta\s+name=["\']generator["\'][^>]*moodle': ("Moodle", 0.95),
    r"/_layouts/": ("SharePoint", 0.8),
    r"/_catalogs/": ("SharePoint", 0.7),
    r"/sharepoint/": ("SharePoint", 0.7),
    r"SharePoint": ("SharePoint", 0.6),
    r"/content/dam/": ("AEM", 0.85),
    r"/crx/de": ("AEM", 0.9),
    r"/etc\.clientlibs/": ("AEM", 0.8),
    r"/libs/granite/": ("AEM", 0.9),
    r"confluence": ("Confluence", 0.6),
    r"/rest/api/content": ("Confluence", 0.8),
    r"ajs-version-number": ("Confluence", 0.9),
    r"/s/en_GB/": ("Confluence", 0.7),
    r"X-Confluence": ("Confluence", 0.9),
    r"/jenkins/": ("Jenkins", 0.7),
    r'<meta\s+name=["\']\.crumb["\']': ("Jenkins", 0.9),
    r"/gitlab/": ("GitLab", 0.7),
    r"gon\.api_version": ("GitLab", 0.9),
    r"gitlab-ce\b|gitlab-ee\b": ("GitLab", 0.9),
    r"/_cluster/health": ("Elasticsearch", 0.9),
    r"elasticsearch": ("Elasticsearch", 0.6),
    r"/sap/bc/": ("SAP", 0.9),
    r"/sap/opu/": ("SAP", 0.85),
    r"SAP NetWeaver": ("SAP", 0.9),
    r"/graphql": ("GraphQL", 0.7),
    r"graphiql": ("GraphQL", 0.8),
    r"/swagger-ui": ("Swagger", 0.8),
    r"swagger-ui-bundle\.js": ("Swagger", 0.9),
    r"openapi": ("Swagger", 0.6),
    r"/docker/": ("Docker", 0.5),
    r"/v2/_catalog": ("Docker Registry", 0.9),
    r"kubernetes": ("Kubernetes", 0.6),
    r"/api/v1/namespaces": ("Kubernetes", 0.9),
}

# ──────────────────── Active Probe Paths ────────────────────

TECH_PROBE_PATHS = [
    # WordPress
    ("wp-login.php", "WordPress"),
    ("wp-admin/", "WordPress"),
    ("wp-content/", "WordPress"),
    ("wp-json/wp/v2/", "WordPress"),
    ("xmlrpc.php", "WordPress"),
    # Joomla
    ("administrator/", "Joomla"),
    ("components/com_content/", "Joomla"),
    ("administrator/manifests/files/joomla.xml", "Joomla"),
    # Drupal
    ("core/CHANGELOG.txt", "Drupal"),
    ("sites/default/", "Drupal"),
    ("user/login", "Drupal"),
    ("core/misc/drupal.js", "Drupal"),
    # PHP
    ("info.php", "PHP"),
    ("phpinfo.php", "PHP"),
    # Tomcat
    ("manager/html", "Tomcat"),
    ("manager/status", "Tomcat"),
    ("host-manager/html", "Tomcat"),
    # IIS
    ("iisstart.htm", "IIS"),
    ("aspnet_client/", "ASP.NET"),
    # Django
    ("admin/", "Django"),
    ("admin/login/", "Django"),
    ("static/admin/css/base.css", "Django"),
    # Laravel
    ("storage/logs/", "Laravel"),
    ("public/index.php", "Laravel"),
    # Rails
    ("rails/info/properties", "Ruby on Rails"),
    # Spring
    ("actuator/health", "Spring"),
    ("actuator/info", "Spring"),
    ("swagger-ui.html", "Spring"),
    # Node.js
    ("package.json", "Node.js"),
    ("server.js", "Node.js"),
    # API Common
    ("api/v1/", "API"),
    ("api/v2/", "API"),
    ("swagger.json", "API"),
    ("openapi.json", "API"),
    ("graphql", "GraphQL"),
    # Magento
    ("magento_version", "Magento"),
    ("skin/frontend/", "Magento"),
    # Ghost
    ("ghost/api/", "Ghost CMS"),
    # TYPO3
    ("typo3/", "TYPO3"),
    ("typo3conf/", "TYPO3"),
    # Umbraco
    ("umbraco/", "Umbraco"),
    ("umbraco/login", "Umbraco"),
    # Magento (additional)
    ("downloader/", "Magento"),
    # Moodle
    ("moodle/", "Moodle"),
    ("login/index.php", "Moodle"),
    ("lib/ajax/", "Moodle"),
    # SharePoint
    ("_layouts/", "SharePoint"),
    ("_catalogs/masterpage/", "SharePoint"),
    ("_vti_pvt/", "SharePoint"),
    # AEM (Adobe Experience Manager)
    ("crx/de", "AEM"),
    ("content/dam/", "AEM"),
    ("system/console", "AEM"),
    ("libs/granite/core/content/login.html", "AEM"),
    # Confluence
    ("rest/api/content", "Confluence"),
    ("login.action", "Confluence"),
    # Jenkins
    ("jenkins/", "Jenkins"),
    ("securityRealm/commenceLogin", "Jenkins"),
    ("login?from=%2F", "Jenkins"),
    # GitLab
    ("users/sign_in", "GitLab"),
    ("-/health", "GitLab"),
    ("explore/projects", "GitLab"),
    # Elasticsearch
    ("_cluster/health", "Elasticsearch"),
    ("_cat/indices", "Elasticsearch"),
    # SAP
    ("sap/bc/gui/sap/its/webgui", "SAP"),
    ("irj/portal", "SAP"),
    # Docker Registry
    ("v2/_catalog", "Docker"),
    ("v2/", "Docker"),
    # Kubernetes
    ("api/v1/namespaces", "Kubernetes"),
    ("healthz", "Kubernetes"),
    # Swagger/OpenAPI
    ("swagger-ui.html", "Swagger"),
    ("swagger.json", "Swagger"),
    ("openapi.json", "Swagger"),
    ("v3/api-docs", "Swagger"),
]

# ─────────────────── Extension Mapping ───────────────────

TECH_EXTENSIONS = {
    "PHP": [".php", ".phtml", ".php3", ".php4", ".php5", ".php7"],
    "WordPress": [".php"],
    "Joomla": [".php"],
    "Drupal": [".php", ".module", ".inc"],
    "Laravel": [".php", ".blade.php"],
    "Symfony": [".php"],
    "CodeIgniter": [".php"],
    "CakePHP": [".php"],
    "ASP.NET": [".aspx", ".asp", ".ashx", ".asmx", ".axd", ".cshtml"],
    "ASP Classic": [".asp"],
    "Java": [".jsp", ".jsf", ".do", ".action"],
    "Tomcat": [".jsp", ".jsf", ".do", ".action"],
    "Spring/Java": [".jsp", ".do", ".action", ".html"],
    "Struts/Java": [".do", ".action"],
    "Ruby on Rails": [".html", ".erb", ".rb"],
    "Django": [".html", ".py"],
    "Flask": [".html", ".py"],
    "Node.js": [".js", ".json", ".html"],
    "Express/Node.js": [".js", ".json", ".html"],
    "Next.js": [".js", ".jsx", ".json", ".html"],
    "Nuxt.js": [".js", ".vue", ".json", ".html"],
    "Python": [".py", ".html"],
    "Perl": [".pl", ".cgi"],
    "Go": [".html"],
    "Rust": [".html"],
    "Magento": [".php", ".phtml"],
    "Magento 2": [".php", ".phtml"],
    "TYPO3": [".php", ".html"],
    "Umbraco": [".aspx", ".ashx", ".cshtml"],
    "Moodle": [".php"],
    "SharePoint": [".aspx", ".ashx", ".asmx"],
    "AEM": [".html", ".json", ".xml"],
    "Confluence": [".action", ".do"],
    "Jenkins": [".html", ".xml"],
    "GitLab": [".html", ".json"],
    "SAP": [".html", ".xml"],
}

# ───────────── Wordlist Mapping (tech → wordlist file) ─────────────

TECH_WORDLIST_MAP = {
    "PHP": "php.txt",
    "WordPress": "wordpress.txt",
    "Joomla": "joomla.txt",
    "Drupal": "drupal.txt",
    "Laravel": "laravel.txt",
    "Apache": "apache.txt",
    "Nginx": "nginx.txt",
    "IIS": "iis.txt",
    "Tomcat": "tomcat.txt",
    "ASP.NET": "asp.txt",
    "ASP Classic": "asp.txt",
    "Java": "jsp.txt",
    "Spring/Java": "spring.txt",
    "Ruby on Rails": "rails.txt",
    "Django": "python_web.txt",
    "Flask": "python_web.txt",
    "Node.js": "nodejs.txt",
    "Express/Node.js": "nodejs.txt",
    "Next.js": "nodejs.txt",
    "API": "api.txt",
    "GraphQL": "graphql.txt",
    "Magento": "magento.txt",
    "Magento 2": "magento.txt",
    "TYPO3": "typo3.txt",
    "Umbraco": "umbraco.txt",
    "Moodle": "moodle.txt",
    "SharePoint": "sharepoint.txt",
    "AEM": "aem.txt",
    "Confluence": "confluence.txt",
    "Jenkins": "jenkins.txt",
    "GitLab": "gitlab.txt",
    "Elasticsearch": "elasticsearch.txt",
    "SAP": "sap.txt",
    "Docker": "docker_kubernetes.txt",
    "Docker Registry": "docker_kubernetes.txt",
    "Kubernetes": "docker_kubernetes.txt",
    "Swagger": "swagger.txt",
    "Ghost CMS": "common.txt",
    "DotNetNuke": "asp.txt",
    "Kentico": "asp.txt",
    "Shopify": "common.txt",
    "PrestaShop": "php.txt",
    "Nuxt.js": "nodejs.txt",
}


class TechDetector:
    def detect_from_response(
        self, headers: Dict, body: str, cookies: Dict
    ) -> TechResult:
        result = TechResult()

        # Server header
        server = headers.get("Server", headers.get("server", ""))
        if server:
            result.server = server
            for pattern, (tech_name, category) in SERVER_SIGNATURES.items():
                if re.search(pattern, server):
                    result.add_technology(tech_name, 0.9)
                    if category == "server":
                        result.server = tech_name

        # X-Powered-By
        powered_by = headers.get(
            "X-Powered-By", headers.get("x-powered-by", "")
        )
        if powered_by:
            for pattern, (tech_name, category) in POWERED_BY_SIGNATURES.items():
                if re.search(pattern, powered_by):
                    result.add_technology(tech_name, 0.9)
                    if category == "language":
                        result.language = tech_name
                    elif category == "framework":
                        result.framework = tech_name

            # Extract PHP version
            php_match = re.search(r"PHP/([\d.]+)", powered_by)
            if php_match:
                result.add_technology("PHP", 0.95)
                result.language = f"PHP {php_match.group(1)}"

            # Extract ASP.NET version
            asp_match = re.search(r"ASP\.NET[\s/]*([\d.]*)", powered_by)
            if asp_match:
                result.add_technology("ASP.NET", 0.95)

        # X-AspNet-Version
        aspnet_ver = headers.get(
            "X-AspNet-Version", headers.get("x-aspnet-version", "")
        )
        if aspnet_ver:
            result.add_technology("ASP.NET", 0.95)

        # X-AspNetMvc-Version
        mvc_ver = headers.get(
            "X-AspNetMvc-Version", headers.get("x-aspnetmvc-version", "")
        )
        if mvc_ver:
            result.add_technology("ASP.NET MVC", 0.95)

        # Check for X-Generator
        generator = headers.get(
            "X-Generator", headers.get("x-generator", "")
        )
        if generator:
            for keyword, tech in [
                ("wordpress", "WordPress"),
                ("drupal", "Drupal"),
                ("joomla", "Joomla"),
                ("typo3", "TYPO3"),
                ("moodle", "Moodle"),
                ("magento", "Magento"),
                ("ghost", "Ghost CMS"),
                ("umbraco", "Umbraco"),
            ]:
                if keyword in generator.lower():
                    result.add_technology(tech, 0.95)
                    result.cms = tech

        # Technology-specific headers
        # Jenkins
        jenkins_hdr = headers.get("X-Jenkins", headers.get("x-jenkins", ""))
        if jenkins_hdr:
            result.add_technology("Jenkins", 0.95)

        # Confluence/Atlassian
        for hdr_name in ["X-Confluence-Request-Time", "X-ASEN",
                         "x-confluence-request-time", "x-asen"]:
            if headers.get(hdr_name, ""):
                result.add_technology("Confluence", 0.9)
                break

        # SharePoint
        sp_hdr = headers.get(
            "MicrosoftSharePointTeamServices",
            headers.get("microsoftsharepointteamservices", "")
        )
        if sp_hdr:
            result.add_technology("SharePoint", 0.95)
        sp_health = headers.get(
            "X-SharePointHealthScore",
            headers.get("x-sharepointhealthscore", "")
        )
        if sp_health:
            result.add_technology("SharePoint", 0.9)

        # Drupal specific headers
        drupal_cache = headers.get(
            "X-Drupal-Cache", headers.get("x-drupal-cache", "")
        )
        if drupal_cache:
            result.add_technology("Drupal", 0.9)
        drupal_dyn = headers.get(
            "X-Drupal-Dynamic-Cache",
            headers.get("x-drupal-dynamic-cache", "")
        )
        if drupal_dyn:
            result.add_technology("Drupal", 0.9)

        # SAP
        sap_hdr = headers.get("sap-server", headers.get("SAP-Server", ""))
        if sap_hdr:
            result.add_technology("SAP", 0.95)

        # AEM / Adobe Experience Manager
        disp_hdr = headers.get(
            "X-Dispatcher", headers.get("x-dispatcher", "")
        )
        if disp_hdr:
            result.add_technology("AEM", 0.7)
        vhost_hdr = headers.get(
            "X-Vhost", headers.get("x-vhost", "")
        )
        if vhost_hdr and disp_hdr:
            result.add_technology("AEM", 0.85)

        # GitLab
        gitlab_hdr = headers.get(
            "X-Gitlab-Meta", headers.get("x-gitlab-meta", "")
        )
        if gitlab_hdr:
            result.add_technology("GitLab", 0.95)

        # Cookie-based detection
        for cookie_name in cookies.keys():
            for pattern, (tech_name, confidence) in COOKIE_SIGNATURES.items():
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    result.add_technology(tech_name, confidence)

        # Body-based detection
        for pattern, (tech_name, confidence) in BODY_SIGNATURES.items():
            if re.search(pattern, body, re.IGNORECASE):
                result.add_technology(tech_name, confidence)

        # OS detection from server header
        if re.search(r"(?i)win|windows|microsoft", server):
            result.os = "Windows"
        elif re.search(r"(?i)ubuntu|debian|centos|rhel|linux|unix", server):
            result.os = "Linux"

        return result

    def get_probe_paths(self) -> List[Tuple[str, str]]:
        return TECH_PROBE_PATHS

    def get_extensions(self, tech_result: TechResult) -> List[str]:
        extensions = set()
        for tech_name in tech_result.technologies:
            for key, exts in TECH_EXTENSIONS.items():
                if key.lower() in tech_name.lower() or tech_name.lower() in key.lower():
                    extensions.update(exts)
        return sorted(extensions)

    def get_wordlists(self, tech_result: TechResult) -> List[str]:
        wordlists = set()
        for tech_name in tech_result.technologies:
            for key, wl_file in TECH_WORDLIST_MAP.items():
                if key.lower() in tech_name.lower() or tech_name.lower() in key.lower():
                    wordlists.add(wl_file)
        return sorted(wordlists)
