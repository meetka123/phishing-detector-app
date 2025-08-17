import re
import tldextract

def extract_features(url):
    ext = tldextract.extract(url)
    hostname = ext.domain + "." + ext.suffix
    path = url.split("/", 3)[-1] if "/" in url else ""

    return {
        "id": 0,
        "NumDots": url.count('.'),
        "SubdomainLevel": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "PathLevel": path.count("/"),
        "UrlLength": len(url),
        "NumDash": url.count('-'),
        "NumDashInHostname": hostname.count('-'),
        "AtSymbol": 1 if "@" in url else 0,
        "TildeSymbol": 1 if "~" in url else 0,
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": url.count('='),
        "NumAmpersand": url.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": 0 if url.startswith("https") else 1,
        "RandomString": 1 if re.search(r'[0-9]{5,}', url) else 0,
        "IpAddress": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "DomainInSubdomains": 1 if ext.domain in ext.subdomain else 0,
        "DomainInPaths": 1 if ext.domain in path else 0,
        "HttpsInHostname": 1 if "https" in hostname else 0,
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(url.split("?")[-1]) if "?" in url else 0,
        "DoubleSlashInPath": path.count("//"),

        # Remaining features default 0
        "NumSensitiveWords": 0,
        "EmbeddedBrandName": 0,
        "PctExtHyperlinks": 0,
        "PctExtResourceUrls": 0,
        "ExtFavicon": 0,
        "InsecureForms": 0,
        "RelativeFormAction": 0,
        "ExtFormAction": 0,
        "AbnormalFormAction": 0,
        "PctNullSelfRedirectHyperlinks": 0,
        "FrequentDomainNameMismatch": 0,
        "FakeLinkInStatusBar": 0,
        "RightClickDisabled": 0,
        "PopUpWindow": 0,
        "SubmitInfoToEmail": 0,
        "IframeOrFrame": 0,
        "MissingTitle": 0,
        "ImagesOnlyInForm": 0,
        "SubdomainLevelRT": 0,
        "UrlLengthRT": 0,
        "PctExtResourceUrlsRT": 0,
        "AbnormalExtFormActionR": 0,
        "ExtMetaScriptLinkRT": 0,
        "PctExtNullSelfRedirectHyperlinksRT": 0
    }
