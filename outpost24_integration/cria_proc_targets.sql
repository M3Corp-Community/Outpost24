CREATE Procedure [dbo].[prcInsertTargets]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into targets
SELECT 
    [TESTCREDXID]
    ,[AUTHENTICATIONTYPE]
    ,[REQUESTBODYBLACKLIST]
	,[HOSTNAME]
    ,[XUPDATOR]
    ,[CREDENTIALPROVIDERID]
    ,[SCANNERNAME]
    ,[MACADDRESS]
    ,[ENABLEREMOTEREGISTRY]
    ,[CVSS_SR_CONF]
    ,[UNGROUPED]
    ,[MACSOURCE]
    ,[COMPLIANCESENABLED]
    ,[CRAWLED]
    ,[LOW_COUNT]
    ,[REACHABLE]
    ,[OUTOFSCOPE]
    ,[SCANLESS_POSSIBLE]
    ,[CONFIRMED]
    ,[BUSINESSCRITICALITY]
    ,[LASTDISCOVERYDATE]
    ,[SCANUPDATEAVAILIBLE]
    ,[VIRTUALHOSTS]
    ,[NEXTSCANDATE]
    ,[BATCHMODE]
    ,[USESLICENSE]
    ,[AUTHENTICATIONRESULT]
    ,[CYBERARKNTLMV1]
    ,[MEDIUM_COUNT]
    ,[XID]
    ,[SCANNERID]
    ,[LOOKUPPERFORMED]
    ,[CYBERARKENABLEREMOTEREGISTRY]
    ,[TEMPLATEOVERRIDE]
    ,[COUNT]
    ,[SYNC]
    ,[IPERCENTV]
    ,[PCICOMPLIANCE]
    ,[HOSTNAMEID]
    ,[XUSERXID]
    ,[LATESTSCANSTATUS]
    ,[CVSS_SR_AVAIL]
    ,[IPADDRESS]
    ,[SMBNTLMV1]
    ,[PLATFORM]
    ,[LATESTSCANDATE]
    ,[PCI] 
    ,[EXPOSED] 
    ,[IGNORECERTS]
    ,[HASDISCOVERYDATA]
    ,[HIDDENURLS]
    ,[CVSS_SR_INTEG]
    ,[CVSS_CDP]
    ,[CVSS_TD]
    ,[URLBLACKLIST]
    ,[COMPLIANT]
    ,[HIGH_COUNT]

FROM OPENJSON(@json)
WITH (
	testcredxid nvarchar(50) '$.testcredxid',
	authenticationtype nvarchar(50) '$.authenticationtype',
	requestbodyblacklist nvarchar(50) '$.requestbodyblacklist',
	hostname nvarchar(50) '$.hostname',
	xupdator nvarchar(50) '$.xupdator',
	credentialproviderid nvarchar(50) '$.credentialproviderid',
	scannername nvarchar(50) '$.scannername',
	macaddress nvarchar(50) '$.macaddress',
	enableremoteregistry nvarchar(50) '$.enableremoteregistry',
	cvss_sr_conf nvarchar(50) '$.cvss_sr_conf',
	ungrouped nvarchar(50) '$.ungrouped',
	macsource nvarchar(50) '$.macsource',
	compliancesenabled nvarchar(50) '$.compliancesenabled',
	crawled nvarchar(50) '$.crawled',
    low_count nvarchar(50) '$.low_count',
    reachable nvarchar(50) '$.reachable',
    outofscope nvarchar(50) '$.outofscope',
    scanless_possible nvarchar(50) '$.scanless_possible',
    confirmed nvarchar(50) '$.confirmed',
    businesscriticality nvarchar(50) '$.businesscriticality',
    lastdiscoverydate nvarchar(50) '$.lastdiscoverydate',
    scanupdateavailible nvarchar(50) '$.scanupdateavailible',
    virtualhosts nvarchar(50) '$.virtualhosts',
    nextscandate nvarchar(50) '$.nextscandate',
    batchmode nvarchar(50) '$.batchmode',
    useslicense nvarchar(50) '$.useslicense',
    authenticationresult nvarchar(50) '$.authenticationresult',
    cyberarkntlmv1 nvarchar(50) '$.cyberarkntlmv1',
    medium_count nvarchar(50) '$.medium_count',
    xid nvarchar(50) '$.xid',
    scannerid nvarchar(50) '$.scannerid',
    lookupperformed nvarchar(50) '$.lookupperformed',
    cyberarkenableremoteregistry nvarchar(50) '$.cyberarkenableremoteregistry',
    templateoverride nvarchar(50) '$.templateoverride',
    count nvarchar(50) '$.count',
    sync nvarchar(50) '$.sync',
    ipercentv nvarchar(50) '$.ipercentv',
    pcicompliance nvarchar(50) '$.pcicompliance',
    hostnameid nvarchar(50) '$.hostnameid',
    xuserxid nvarchar(50) '$.xuserxid',
    latestscanstatus nvarchar(50) '$.latestscanstatus',
    cvss_sr_avail nvarchar(50) '$.cvss_sr_avail',
    ipaddress nvarchar(50) '$.ipaddress',
    smbntlmv1 nvarchar(50) '$.smbntlmv1',
    platform nvarchar(50) '$.platform',
    latestscandate nvarchar(50) '$.latestscandate',
    pci  nvarchar(50) '$.pci ',
    exposed  nvarchar(50) '$.exposed ',
    ignorecerts nvarchar(50) '$.ignorecerts',
    hasdiscoverydata nvarchar(50) '$.hasdiscoverydata',
    hiddenurls nvarchar(50) '$.hiddenurls',
    cvss_sr_integ nvarchar(50) '$.cvss_sr_integ',
    cvss_cdp nvarchar(50) '$.cvss_cdp',
    cvss_td nvarchar(50) '$.cvss_td',
    urlblacklist nvarchar(50) '$.urlblacklist',
    compliant nvarchar(50) '$.compliant',
    high_count nvarchar(50) '$.high_count'
	) AS JSON_VALUES

END