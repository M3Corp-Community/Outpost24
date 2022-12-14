CREATE Procedure [dbo].[prcInsertVulnerability]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into VulnerabilityDb
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
