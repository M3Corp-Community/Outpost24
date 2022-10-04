USE [API_teste]
GO
/****** Object:  StoredProcedure [dbo].[prcInsertFindings]    Script Date: 24/08/2022 11:29:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE Procedure [dbo].[prcInsertFindings]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into findings
SELECT 
	  [TENANT_ID]
	  ,[ACCEPTCOMMENT]
      ,[ACCEPTDATE]
      ,[ACCEPTED]
      ,[ACCEPTEDBY]
      ,[ACCEPTEDLENGTH]
      ,[ACCEPTEXPIRES]
      ,[AGE]
      ,[ATTACHMENTS]
      ,[BFALSEPOS]
      ,[BNEW]
      ,[BPCI]
      ,[BUSINESSCRITICALITY]
      ,[CVSSSCORE]
      ,[CVSSV3SCORE]
      ,[CVSSV3SEVERITY]
      ,[CYRATING]
      ,[CYRATINGDELTA]
      ,[CYRATINGLASTSEEN]
      ,[CYRATINGUPDATED]
      ,[CUSTOM0]
      ,[CUSTOM1]
      ,[CUSTOM2]
      ,[CUSTOM3]
      ,[CUSTOM4]
      ,[CUSTOM5]
      ,[CUSTOM6]
      ,[CUSTOM7]
      ,[CUSTOM8]
      ,[CUSTOM9]
      ,[DATE]
      ,[DFIRSTSEEN]
      ,[DLASTSEEN]
      ,[EXPLOITPROBABILITY]
      ,[EXPLOITPROBABILITYDELTA]
      ,[EXPOSED]
      ,[FINDINGDATE]
      ,[FIXED]
      ,[HASEXPLOITS]
      ,[HASFPCOMMENT]
      ,[HOSTNAME]
      ,[IPORT]
      ,[IPROTOCOL]
      ,[IRISK]
      ,[ISADDED]
      ,[ITYPE]
      ,[OLDDISPUTEACCEPTEDID]
      ,[ORIGINALRISKLEVEL]
      ,[PCICVSSSCORE]
      ,[PLATFORM]
      ,[POTENTIALFALSE]
      ,[PREVIOUSLYDETECTED]
      ,[PRODUCT]
      ,[PRODUCTURL]
      ,[REPORTXID]
      ,[SCANNERID]
      ,[SCRIPTCREATED]
      ,[SERVICENAME]
      ,[SOLUTIONTYPE]
      ,[STILLPRESENT]
      ,[TARGETTYPE]
      ,[TASKID]
      ,[TICKETXID]
      ,[TYPE]
      ,[VCBUG]
      ,[VCCVE]
      ,[VCFAMILY]
      ,[VCNAME]
      ,[VCTARGET]
      ,[VCVULNID]
      ,[VERIFIED]
      ,[VULNERABILITYTYPE]
      ,[WASFINDING]
      ,[XID]
      ,[XIPXID]
      ,[XTEMPLATE]
	FROM OPENJSON(@json)
	WITH (
		tenant_id int '$.tenant_id',
		acceptcomment nvarchar(max) '$.acceptcomment',
		acceptdate nvarchar(50) '$.acceptdate',
		accepted nvarchar(50) '$.accepted',
		acceptedby nvarchar(50) '$.acceptedby',
		acceptedlength nvarchar(50) '$.acceptedlength',
		acceptexpires nvarchar(50) '$.acceptexpires',
		age nvarchar(50) '$.age',
		attachments nvarchar(50) '$.attachments',
		bfalsepos nvarchar(50) '$.bfalsepos',
		bnew nvarchar(50) '$.bnew',
		bpci nvarchar(50) '$.bpci',
		businesscriticality nvarchar(50) '$.businesscriticality',
		cvssscore nvarchar(50) '$.cvssscore',
		cvssv3score nvarchar(50) '$.cvssv3score',
		cvssv3severity nvarchar(50) '$.cvssv3severity',
		cyrating nvarchar(50) '$.cyrating',
		cyratingdelta nvarchar(50)  '$.cyratingdelta',
		cyratinglastseen nvarchar(50) '$.cyratinglastseen',
		cyratingupdated nvarchar(50) '$.cyratingupdated',
		custom0 nvarchar(150) '$.custom0',
		custom1 nvarchar(150) '$.custom1',
		custom2 nvarchar(150) '$.custom2',
		custom3 nvarchar(150) '$.custom3',
		custom4 nvarchar(150) '$.custom4',
		custom5 nvarchar(150) '$.custom5',
		custom6 nvarchar(150) '$.custom6',
		custom7 nvarchar(150) '$.custom7',
		custom8 nvarchar(150) '$.custom8',
		custom9 nvarchar(150) '$.custom9',
		date nvarchar(50) '$.date',
		dfirstseen nvarchar(50) '$.dfirstseen',
		dlastseen nvarchar(50) '$.dlastseen',
		exploitprobability nvarchar(50) '$.exploitprobability',
		exploitprobabilitydelta nvarchar(50) '$.exploitprobabilitydelta',
		exposed nvarchar(50) '$.exposed',
		findingdate nvarchar(50) '$.findingdate',
		fixed nvarchar(50) '$.fixed',
		hasexploits nvarchar(50) '$.hasexploits',
		hasfpcomment nvarchar(50) '$.hasfpcomment',
		hostname nvarchar(100) '$.hostname',
		iport nvarchar(50) '$.iport',
		iprotocol nvarchar(50) '$.iprotocol',
		irisk nvarchar(50) '$.irisk',
		isadded nvarchar(50) '$.isadded',
		itype nvarchar(50) '$.itype',
		olddisputeacceptedid nvarchar(50) '$.olddisputeacceptedid',
		originalrisklevel nvarchar(50) '$.originalrisklevel',
		pcicvssscore nvarchar(50) '$.pcicvssscore',
		platform nvarchar(200) '$.platform',
		potentialfalse nvarchar(50) '$.potentialfalse',
		previouslydetected nvarchar(50) '$.previouslydetected',
		product nvarchar(200) '$.product',
		producturl nvarchar(500) '$.producturl',
		reportxid nvarchar(50) '$.reportxid',
		scannerid nvarchar(50) '$.scannerid',
		scriptcreated nvarchar(50) '$.scriptcreated',
		servicename nvarchar(150) '$.servicename',
		solutiontype nvarchar(50) '$.solutiontype',
		stillpresent nvarchar(50) '$.stillpresent',
		targettype nvarchar(50) '$.targettype',
		taskid nvarchar(50) '$.taskid',
		ticketxid nvarchar(50) '$.ticketxid',
		type nvarchar(150) '$.type',
		vcbug nvarchar(50) '$.vcbug',
		vccve nvarchar(50) '$.vccve',
		vcfamily nvarchar(50) '$.vcfamily',
		vcname nvarchar(500) '$.vcname',
		vctarget nvarchar(500) '$.vctarget',
		vcvulnid nvarchar(50) '$.vcvulnid',
		verified nvarchar(50) '$.verified',
		vulnerabilitytype nvarchar(50) '$.vulnerabilitytype',
		wasfinding nvarchar(50) '$.wasfinding',
		xid nvarchar(50) '$.xid',
		xipxid nvarchar(50) '$.xipxid',
		xtemplate nvarchar(50)  '$.xtemplate'
		) AS JSON_VALUES

END
GO
/****** Object:  StoredProcedure [dbo].[prcInsertGroups]    Script Date: 24/08/2022 11:29:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE Procedure [dbo].[prcInsertGroups]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into Groups
SELECT 
    [RULEBASED]
    ,[DESCRIPTION]
    ,[RULE]
    ,[REPORTBASED]
    ,[XID]
    ,[ICOUNT]
    ,[PCI]
    ,[XUSERXID]
    ,[NAME]
    ,[XIPARENTID]

FROM OPENJSON(@json)
WITH (
    rulebased nvarchar(50) '$.rulebased',
    description nvarchar(50) '$.description',
    "rule" nvarchar(50) '$.rule',
    reportbased nvarchar(50) '$.reportbased',
    xid nvarchar(50) '$.xid',
    icount nvarchar(50) '$.icount',
    pci nvarchar(50) '$.pci',
    xuserxid nvarchar(50) '$.xuserxid',
    name nvarchar(50) '$.name',
    xiparentid nvarchar(50) '$.xiparentid'
	) AS JSON_VALUES

END
GO
/****** Object:  StoredProcedure [dbo].[prcInsertScan_history]    Script Date: 24/08/2022 11:29:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE Procedure [dbo].[prcInsertScan_history]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into scan_history
SELECT 
	   [XID]
      ,[HIGH]
      ,[SCANNERID]
      ,[SCANNERNAME]
      ,[LAST]
      ,[SCANLESSREPORTXID]
      ,[PREVMEDIUM]
      ,[VCHOST]
      ,[TARGETGROUPXID]
      ,[DUPDATED]
      ,[CANUPDATE]
      ,[BLUEPRINT]
      ,[SCANTIME]
      ,[SUBMITTED]
      ,[XUSERXID]
      ,[SCHEDULEJOB]
      ,[XTEMPLATE]
      ,[TEMPLATE]
      ,[DCREATED]
      ,[IID]
      ,[XSUBUSERXID]
      ,[PREVHIGH]
      ,[PREVLOW]
      ,[LATESTRULEDATE]
      ,[DSCANSTARTDATE]
      ,[MEDIUM]
      ,[CONFIRMED]
      ,[LATESTSCANUPDATE]
      ,[XIPXID]
      ,[FROMHIAB]
      ,[LOW]
      ,[HASWASSTATS]
      ,[ITYPE]
      ,[COMPLIANCESCAN]
      ,[XSCHEDULEXID]
      ,[SCANLESS]
      ,[BDELETED]
      ,[TARGET]
      ,[XSOXID]
      ,[DISCOVERY]
      ,[DSCANENDDATE]
      ,[COMPLIANT]
      ,[LASTREPORT]
      ,[XSCANJOBXID]
      ,[VCCOUNTRY]

FROM OPENJSON(@json)
WITH (
    xid nvarchar(50) '$.xid',
   "high" nvarchar(50) '$.high',
    scannerid nvarchar(50) '$.scannerid',
    scannername nvarchar(50) '$.scannername',
    "last" nvarchar(50) '$.last',
    scanlessreportxid nvarchar(50) '$.scanlessreportxid',
    prevmedium nvarchar(50) '$.prevmedium',
    vchost nvarchar(50) '$.vchost',
    targetgroupxid nvarchar(50) '$.targetgroupxid',
    dupdated nvarchar(50) '$.dupdated',
    canupdate nvarchar(50) '$.canupdate',
    blueprint nvarchar(50) '$.blueprint',
    scantime nvarchar(50) '$.scantime',
    submitted nvarchar(50) '$.submitted',
    xuserxid nvarchar(50) '$.xuserxid',
    schedulejob nvarchar(50) '$.schedulejob',
    xtemplate nvarchar(50) '$.xtemplate',
    template nvarchar(50) '$.template',
    dcreated nvarchar(50) '$.dcreated',
    iid nvarchar(50) '$.iid',
    xsubuserxid nvarchar(50) '$.xsubuserxid',
    prevhigh nvarchar(50) '$.prevhigh',
    prevlow nvarchar(50) '$.prevlow',
    latestruledate nvarchar(50) '$.latestruledate',
    dscanstartdate nvarchar(50) '$.dscanstartdate',
    medium nvarchar(50) '$.medium',
    confirmed nvarchar(50) '$.confirmed',
    latestscanupdate nvarchar(50) '$.latestscanupdate',
    xipxid nvarchar(50) '$.xipxid',
    fromhiab nvarchar(50) '$.fromhiab',
    "low" nvarchar(50) '$.low',
    haswasstats nvarchar(50) '$.haswasstats',
    itype nvarchar(50) '$.itype',
    compliancescan nvarchar(50) '$.compliancescan',
    xschedulexid nvarchar(50) '$.xschedulexid',
    scanless nvarchar(50) '$.scanless',
    bdeleted nvarchar(50) '$.bdeleted',
    "target" nvarchar(50) '$.target',
    xsoxid nvarchar(50) '$.xsoxid',
    discovery nvarchar(50) '$.discovery',
    dscanenddate nvarchar(50) '$.dscanenddate',
    compliant nvarchar(50) '$.compliant',
    lastreport nvarchar(50) '$.lastreport',
    xscanjobxid nvarchar(50) '$.xscanjobxid',
    vccountry nvarchar(50) '$.vccountry'
    	) AS JSON_VALUES

END
GO
/****** Object:  StoredProcedure [dbo].[prcInsertTargets]    Script Date: 24/08/2022 11:29:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

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
GO
/****** Object:  StoredProcedure [dbo].[prcInsertvulnerability]    Script Date: 24/08/2022 11:29:42 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE Procedure [dbo].[prcInsertvulnerability]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into vulnerability_db
SELECT 
	  [CDESC]
      ,[CSOL]
      ,[CUSTOMRISK]
      ,[CVSS_SCORE]
      ,[CYRATING]
      ,[CYRATINGDELTA]
      ,[CYRATINGLASTSEEN]
      ,[CYRATINGUPDATED]
      ,[EXPLOITPROBABILITY]
      ,[EXPLOITPROBABILITYDELTA]
      ,[HASEXPLOITS]
      ,[ICVSS]
      ,[IPCICVSS]
      ,[IRISK]
      ,[OSVDB]
      ,[PCIFAIL]
      ,[PREVIOUSCYRATING]
      ,[PREVIOUSEXPLOITPROBABILITY]
      ,[SCRIPTCREATED]
      ,[SOLUTIONPRODUCT]
      ,[SOLUTIONTITLE]
      ,[SOLUTIONTYPE]
      ,[VCBUG]
      ,[VCCVE]
      ,[VCCVSSVECTOR]
      ,[VCFAM]
      ,[VCNAME]
      ,[WAS_FALSEPOS]
      ,[WAS_INFORMATIONAL]
      ,[WASC]
      ,[XID]
	FROM OPENJSON(@json)
	WITH (
		cdesc nvarchar(max) '$.cdesc',
		csol nvarchar(50) '$.csol',
		customrisk nvarchar(500) '$.customrisk',
		cvss_score nvarchar(50) '$.cvss_score',
		cyrating nvarchar(50) '$.cyrating',
		cyratingdelta nvarchar(50) '$.cyratingdelta',
		cyratinglastseen nvarchar(50) '$.cyratinglastseen',
		cyratingupdated nvarchar(50) '$.cyratingupdated',
		exploitprobability nvarchar(50) '$.exploitprobability',
		exploitprobabilitydelta nvarchar(50) '$.exploitprobabilitydelta',
		hasexploits nvarchar(50) '$.hasexploits',
		icvss nvarchar(50) '$.icvss',
		ipcicvss nvarchar(50) '$.ipcicvss',
		irisk nvarchar(50) '$.irisk',
		osvdb nvarchar(50) '$.osvdb',
		pcifail nvarchar(50) '$.pcifail',
		previouscyrating nvarchar(50) '$.previouscyrating',
		previousexploitprobability nvarchar(50) '$.previousexploitprobability',
		scriptcreated nvarchar(50) '$.scriptcreated',
		solutionproduct nvarchar(50) '$.solutionproduct',
		solutiontitle nvarchar(50) '$.solutiontitle',
		solutiontype nvarchar(50) '$.solutiontype',
		vcbug nvarchar(50) '$.vcbug',
		vccve nvarchar(50) '$.vccve',
		vccvssvector nvarchar(50) '$.vccvssvector',
		vcfam nvarchar(50) '$.vcfam',
		vcname nvarchar(50) '$.vcname',
		was_falsepos nvarchar(50) '$.was_falsepos',
		was_informational nvarchar(50) '$.was_informational',
		wasc nvarchar(50) '$.wasc',
		xid nvarchar(50) '$.xid'
		) AS JSON_VALUES

END
GO
