
This module allows SAML Trust Security Token Service (STS) authentication.
General standard is:
[1] http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
Federation service is provided using Microsoft technologies, which are briefly described here:
[2] http://msdn.microsoft.com/en-us/library/ee517291.aspx 
[3] http://msdn.microsoft.com/en-us/library/bb498017.aspx 
[4] http://msdn.microsoft.com/en-us/library/bb608217.aspx 

The following XWiki Class should be created in /xwiki/bin/view/XWiki/XWikiClasses designer:


XWiki.STSAuthClass
with fields:
* nameid OR personid as String (depending on configuration) 
* authtype as String
(There is no need for Sheet and Template documents)

The following configuration is needed in xwiki.cfg

##  Xwiki authentication class 
xwiki.authentication.authclass=com.xwiki.authentication.sts.XWikiSTSAuthenticator
# SAML STS xml element for user ID
xwiki.authentication.sts.id_field=privatepersonalidentifier
# XWiki.XWikiUsers class field mapping to STS response fields
xwiki.authentication.sts.field_mapping=first_name=givenname,last_name=surname,
# Xwiki context field to apply STS authentication
xwiki.authentication.sts.auth_field=sts_user
# Xwiki user name creation rule
xwiki.authentication.sts.xwiki_username_rule=first_name,last_name
# How should format user data (CAPITAL|Title|0)
xwiki.authentication.sts.data_format=Title
## STS provider URL
#xwiki.authentication.sts.authurl=https://ivis.eps.gov.lv/IVIS.LVP.STS/Default.aspx
xwiki.authentication.sts.authurl=https://epakvisstv.vraa.gov.lv/STS/VISS.LVP.STS/Default.aspx
## STS service configuration
# Unique ID (usually URI) of the request realm
xwiki.authentication.sts.wtrealm=https://pakalpojumi.carnikava.lv/prod
# Use unique request/context ID (1|0)
xwiki.authentication.sts.wctx=1
# Start of URL to which response is redirected (0|fixed_string, e.g. http://localhost:8080)
xwiki.authentication.sts.wreply_host=https://85.254.250.27
# Page of URL to which response is redirected (1|shorten|fixed_string, e.g. /xwiki/bin/view/Main/WebHome)
xwiki.authentication.sts.wreply_page=shorten
# Send current time of the sender (1|0)
xwiki.authentication.sts.wct=1
# desired maximum age of authentication (in minutes)
xwiki.authentication.sts.wfresh=1
# Issuer attribute value of the XML saml:Assertion element
xwiki.authentication.sts.issuer=http://www.latvija.lv/sts
# AudienceURIs of the X509 certificate
xwiki.authentication.sts.audience_uris=https://pakalpojumi.carnikava.lv/prod
# Local X509 certificate (if set and file is valid certificate - user provided certificates will be compared with this (trusted) certificate
xwiki.authentication.sts.cert_filename=/home/webapps/xwiki/WEB-INF/VISS.LVP.STS.cer
# Entity ID of the X509 certificate (this value is used only if local X509 certificate is not set)
xwiki.authentication.sts.entity_id=http://www.latvija.lv/sts
# IssuerDN of the X509 certificate  (this value is used only if local X509 certificate is not set)
xwiki.authentication.sts.issuer_dn=CN=VISS Root CA, DC=viss, DC=int
# SubjectDNs of the X509 certificate  (this value is used only if local X509 certificate is not set)
xwiki.authentication.sts.subject_dns=EMAILADDRESS=cisu.help@vraa.gov.lv, CN=VISS.LVP.STS, OU=VPISD, O=VRAA, L=Riga, ST=Riga, C=LV
