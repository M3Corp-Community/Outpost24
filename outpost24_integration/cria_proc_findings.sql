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