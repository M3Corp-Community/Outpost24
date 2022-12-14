CREATE Procedure [dbo].[prcInsertScanHistory]
(
	@json VARCHAR(MAX) = ''
)
AS
BEGIN


INSERT into scanHistory
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


