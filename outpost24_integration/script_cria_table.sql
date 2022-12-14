USE [|######|]

CREATE TABLE [dbo].[AuditAplications](
	[VALUE] [nvarchar](50) NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
 CONSTRAINT [xid_AuditAplications] UNIQUE NONCLUSTERED 
(
	[VALUE] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

CREATE TABLE [dbo].[ErrorCodes](
	[ERROR] [int] NOT NULL,
	[MESSAGE] [nvarchar](100) NULL,
	[EXTENDED_EXPLANATION] [nvarchar](300) NULL,
 CONSTRAINT [xid_ErrorCodes] UNIQUE NONCLUSTERED 
(
	[ERROR] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[EventType]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[EventType](
	[TYPE] [int] NOT NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
 CONSTRAINT [xid_EventType] UNIQUE NONCLUSTERED 
(
	[TYPE] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[findings]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[Findings](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[TENANT_ID] [int] NOT NULL,
	[ACCEPTCOMMENT] [nvarchar](max) NULL,
	[ACCEPTDATE] [nvarchar](50) NOT NULL,
	[ACCEPTED] [nvarchar](50) NOT NULL,
	[ACCEPTEDBY] [nvarchar](50) NULL,
	[ACCEPTEDLENGTH] [nvarchar](50) NULL,
	[ACCEPTEXPIRES] [nvarchar](50) NOT NULL,
	[AGE] [nvarchar](50) NOT NULL,
	[ATTACHMENTS] [nvarchar](50) NULL,
	[BFALSEPOS] [nvarchar](50) NULL,
	[BNEW] [nvarchar](50) NULL,
	[BPCI] [nvarchar](50) NULL,
	[BUSINESSCRITICALITY] [nvarchar](50) NULL,
	[CVSSSCORE] [nvarchar](50) NULL,
	[CVSSV3SCORE] [nvarchar](50) NULL,
	[CVSSV3SEVERITY] [nvarchar](50) NULL,
	[CYRATING] [nvarchar](50) NULL,
	[CYRATINGDELTA] [nvarchar](50) NULL,
	[CYRATINGLASTSEEN] [nvarchar](50) NULL,
	[CYRATINGUPDATED] [nvarchar](50) NULL,
	[CUSTOM0] [nvarchar](150) NULL,
	[CUSTOM1] [nvarchar](150) NULL,
	[CUSTOM2] [nvarchar](150) NULL,
	[CUSTOM3] [nvarchar](150) NULL,
	[CUSTOM4] [nvarchar](150) NULL,
	[CUSTOM5] [nvarchar](150) NULL,
	[CUSTOM6] [nvarchar](150) NULL,
	[CUSTOM7] [nvarchar](150) NULL,
	[CUSTOM8] [nvarchar](150) NULL,
	[CUSTOM9] [nvarchar](150) NULL,
	[DATE] [nvarchar](50) NULL,
	[DFIRSTSEEN] [nvarchar](50) NOT NULL,
	[DLASTSEEN] [nvarchar](50) NOT NULL,
	[EXPLOITPROBABILITY] [nvarchar](50) NULL,
	[EXPLOITPROBABILITYDELTA] [nvarchar](50) NULL,
	[EXPOSED] [nvarchar](50) NULL,
	[FINDINGDATE] [nvarchar](50) NOT NULL,
	[FIXED] [nvarchar](50) NULL,
	[HASEXPLOITS] [nvarchar](50) NULL,
	[HASFPCOMMENT] [nvarchar](50) NULL,
	[HOSTNAME] [nvarchar](100) NULL,
	[IPORT] [nvarchar](50) NOT NULL,
	[IPROTOCOL] [nvarchar](50) NULL,
	[IRISK] [nvarchar](50) NULL,
	[ISADDED] [nvarchar](50) NULL,
	[ITYPE] [nvarchar](50) NULL,
	[OLDDISPUTEACCEPTEDID] [nvarchar](50) NULL,
	[ORIGINALRISKLEVEL] [nvarchar](50) NULL,
	[PCICVSSSCORE] [nvarchar](50) NULL,
	[PLATFORM] [nvarchar](200) NULL,
	[POTENTIALFALSE] [nvarchar](50) NULL,
	[PREVIOUSLYDETECTED] [nvarchar](50) NULL,
	[PRODUCT] [nvarchar](200) NULL,
	[PRODUCTURL] [nvarchar](500) NULL,
	[REPORTXID] [nvarchar](50) NULL,
	[SCANNERID] [nvarchar](50) NULL,
	[SCRIPTCREATED] [nvarchar](50) NULL,
	[SERVICENAME] [nvarchar](150) NULL,
	[SOLUTIONTYPE] [nvarchar](50) NULL,
	[STILLPRESENT] [nvarchar](50) NULL,
	[TARGETTYPE] [nvarchar](50) NULL,
	[TASKID] [nvarchar](50) NULL,
	[TICKETXID] [nvarchar](50) NULL,
	[TYPE] [nvarchar](150) NULL,
	[VCBUG] [nvarchar](50) NULL,
	[VCCVE] [nvarchar](50) NULL,
	[VCFAMILY] [nvarchar](50) NULL,
	[VCNAME] [nvarchar](500) NULL,
	[VCTARGET] [nvarchar](500) NOT NULL,
	[VCVULNID] [nvarchar](50) NOT NULL,
	[VERIFIED] [nvarchar](50) NULL,
	[VULNERABILITYTYPE] [nvarchar](50) NULL,
	[WASFINDING] [nchar](10) NULL,
	[XID] [nvarchar](50) NOT NULL,
	[XIPXID] [nvarchar](50) NOT NULL,
	[XTEMPLATE] [nvarchar](50) NULL,
 CONSTRAINT [xid] UNIQUE NONCLUSTERED 
(
	[XID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

/****** Object:  Table [dbo].[groups]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[Groups](
	[RULEBASED] [nvarchar](50) NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
	[RULE] [nvarchar](max) NULL,
	[REPORTBASED] [nvarchar](50) NULL,
	[XID] [nvarchar](50) NULL,
	[ICOUNT] [nvarchar](50) NULL,
	[PCI] [nvarchar](50) NULL,
	[XUSERXID] [nvarchar](50) NULL,
	[NAME] [nvarchar](50) NULL,
	[XIPARENTID] [nvarchar](50) NULL,
 CONSTRAINT [xid_groups] UNIQUE NONCLUSTERED 
(
	[XID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

/****** Object:  Table [dbo].[ReportTypes]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[ReportTypes](
	[TYPE] [int] NOT NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
 CONSTRAINT [xid_ReportTypes] UNIQUE NONCLUSTERED 
(
	[TYPE] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[RiskTable]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[RiskTable](
	[RISK] [int] NOT NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
 CONSTRAINT [xid_RiskTable] UNIQUE NONCLUSTERED 
(
	[RISK] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[scan_history]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[ScanHistory](
	[XID] [nvarchar](50) NULL,
	[HIGH] [nvarchar](50) NULL,
	[SCANNERID] [nvarchar](50) NULL,
	[SCANNERNAME] [nvarchar](50) NULL,
	[LAST] [nvarchar](50) NULL,
	[SCANLESSREPORTXID] [nvarchar](50) NULL,
	[PREVMEDIUM] [nvarchar](50) NULL,
	[VCHOST] [nvarchar](50) NULL,
	[TARGETGROUPXID] [nvarchar](50) NULL,
	[DUPDATED] [nvarchar](50) NULL,
	[CANUPDATE] [nvarchar](50) NULL,
	[BLUEPRINT] [nvarchar](50) NULL,
	[SCANTIME] [nvarchar](50) NULL,
	[SUBMITTED] [nvarchar](50) NULL,
	[XUSERXID] [nvarchar](50) NULL,
	[SCHEDULEJOB] [nvarchar](50) NULL,
	[XTEMPLATE] [nvarchar](50) NULL,
	[TEMPLATE] [nvarchar](50) NULL,
	[DCREATED] [nvarchar](50) NULL,
	[IID] [nvarchar](50) NULL,
	[XSUBUSERXID] [nvarchar](50) NULL,
	[PREVHIGH] [nvarchar](50) NULL,
	[PREVLOW] [nvarchar](50) NULL,
	[LATESTRULEDATE] [nvarchar](50) NULL,
	[DSCANSTARTDATE] [nvarchar](50) NULL,
	[MEDIUM] [nvarchar](50) NULL,
	[CONFIRMED] [nvarchar](50) NULL,
	[LATESTSCANUPDATE] [nvarchar](50) NULL,
	[XIPXID] [nvarchar](50) NULL,
	[FROMHIAB] [nvarchar](50) NULL,
	[LOW] [nvarchar](50) NULL,
	[HASWASSTATS] [nvarchar](50) NULL,
	[ITYPE] [nvarchar](50) NULL,
	[COMPLIANCESCAN] [nvarchar](50) NULL,
	[XSCHEDULEXID] [nvarchar](50) NULL,
	[SCANLESS] [nvarchar](50) NULL,
	[BDELETED] [nvarchar](50) NULL,
	[TARGET] [nvarchar](50) NULL,
	[XSOXID] [nvarchar](50) NULL,
	[DISCOVERY] [nvarchar](50) NULL,
	[DSCANENDDATE] [nvarchar](50) NULL,
	[COMPLIANT] [nvarchar](50) NULL,
	[LASTREPORT] [nvarchar](50) NULL,
	[XSCANJOBXID] [nvarchar](50) NULL,
	[VCCOUNTRY] [nvarchar](50) NULL,
 CONSTRAINT [xid_ScanHistory] UNIQUE NONCLUSTERED 
(
	[XID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[ScanStatusTable]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[ScanStatusTable](
	[SCANSTATUSCODE] [int] NOT NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
 CONSTRAINT [xid_ScanStatusTable] UNIQUE NONCLUSTERED 
(
	[SCANSTATUSCODE] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[ScheduleFreqTable]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[ScheduleFreqTable](
	[SCHEDULE_CODE] [int] NOT NULL,
	[FREQUENCY] [nvarchar](50) NULL,
 CONSTRAINT [xid_ScheduleFreqTable] UNIQUE NONCLUSTERED 
(
	[SCHEDULE_CODE] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[Solutiontype]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[SolutionType](
	[TYPE] [int] NOT NULL,
	[DESCRIPTION] [nvarchar](50) NULL,
 CONSTRAINT [xid_SolutionType] UNIQUE NONCLUSTERED 
(
	[TYPE] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[targets]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[Targets](
	[TESTCREDXID] [nvarchar](50) NULL,
	[AUTHENTICATIONTYPE] [nvarchar](50) NULL,
	[REQUESTBODYBLACKLIST] [nvarchar](50) NULL,
	[HOSTNAME] [nvarchar](50) NULL,
	[XUPDATOR] [nvarchar](50) NULL,
	[CREDENTIALPROVIDERID] [nvarchar](50) NULL,
	[SCANNERNAME] [nvarchar](50) NULL,
	[MACADDRESS] [nvarchar](50) NULL,
	[ENABLEREMOTEREGISTRY] [nvarchar](50) NULL,
	[CVSS_SR_CONF] [nvarchar](50) NULL,
	[UNGROUPED] [nvarchar](50) NULL,
	[MACSOURCE] [nvarchar](50) NULL,
	[COMPLIANCESENABLED] [nvarchar](50) NULL,
	[CRAWLED] [nvarchar](50) NULL,
	[LOW_COUNT] [nvarchar](50) NULL,
	[REACHABLE] [nvarchar](50) NULL,
	[OUTOFSCOPE] [nvarchar](50) NULL,
	[SCANLESS_POSSIBLE] [nvarchar](50) NULL,
	[CONFIRMED] [nvarchar](50) NULL,
	[BUSINESSCRITICALITY] [nvarchar](50) NULL,
	[LASTDISCOVERYDATE] [nvarchar](50) NULL,
	[SCANUPDATEAVAILIBLE] [nvarchar](50) NULL,
	[VIRTUALHOSTS] [nvarchar](50) NULL,
	[NEXTSCANDATE] [nvarchar](50) NULL,
	[BATCHMODE] [nvarchar](50) NULL,
	[USESLICENSE] [nvarchar](50) NULL,
	[AUTHENTICATIONRESULT] [nvarchar](50) NULL,
	[CYBERARKNTLMV1] [nvarchar](50) NULL,
	[MEDIUM_COUNT] [nvarchar](50) NULL,
	[XID] [nvarchar](50) NULL,
	[SCANNERID] [nvarchar](50) NULL,
	[LOOKUPPERFORMED] [nvarchar](50) NULL,
	[CYBERARKENABLEREMOTEREGISTRY] [nvarchar](50) NULL,
	[TEMPLATEOVERRIDE] [nvarchar](50) NULL,
	[COUNT] [nvarchar](50) NULL,
	[SYNC] [nvarchar](50) NULL,
	[IPERCENTV] [nvarchar](50) NULL,
	[PCICOMPLIANCE] [nvarchar](50) NULL,
	[HOSTNAMEID] [nvarchar](50) NULL,
	[XUSERXID] [nvarchar](50) NULL,
	[LATESTSCANSTATUS] [nvarchar](50) NULL,
	[CVSS_SR_AVAIL] [nvarchar](50) NULL,
	[IPADDRESS] [nvarchar](50) NULL,
	[SMBNTLMV1] [nvarchar](50) NULL,
	[PLATFORM] [nvarchar](50) NULL,
	[LATESTSCANDATE] [nvarchar](50) NULL,
	[PCI] [nvarchar](50) NULL,
	[EXPOSED] [nvarchar](50) NULL,
	[IGNORECERTS] [nvarchar](50) NULL,
	[HASDISCOVERYDATA] [nvarchar](50) NULL,
	[HIDDENURLS] [nvarchar](50) NULL,
	[CVSS_SR_INTEG] [nvarchar](50) NULL,
	[CVSS_CDP] [nvarchar](50) NULL,
	[CVSS_TD] [nvarchar](50) NULL,
	[URLBLACKLIST] [nvarchar](50) NULL,
	[COMPLIANT] [nvarchar](50) NULL,
	[HIGH_COUNT] [nvarchar](50) NULL,
 CONSTRAINT [xid_Targets] UNIQUE NONCLUSTERED 
(
	[XID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[tenants]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[Tenants](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[tenant] [nvarchar](100) NOT NULL,
	[token] [nvarchar](300) NOT NULL,
	[status] [int] NOT NULL,
	[host] [nvarchar](150) NOT NULL,
	[image] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

/****** Object:  Table [dbo].[vulnerability_db]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[VulnerabilityDb](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[CDESC] [nvarchar](max) NULL,
	[CSOL] [nvarchar](50) NULL,
	[CUSTOMRISK] [nvarchar](50) NULL,
	[CVSS_SCORE] [nvarchar](50) NULL,
	[CYRATING] [nvarchar](50) NULL,
	[CYRATINGDELTA] [nvarchar](50) NULL,
	[CYRATINGLASTSEEN] [nvarchar](50) NULL,
	[CYRATINGUPDATED] [nvarchar](50) NULL,
	[EXPLOITPROBABILITY] [nvarchar](50) NULL,
	[EXPLOITPROBABILITYDELTA] [nvarchar](50) NULL,
	[HASEXPLOITS] [nvarchar](50) NULL,
	[ICVSS] [nvarchar](50) NULL,
	[IPCICVSS] [nvarchar](50) NULL,
	[IRISK] [nvarchar](50) NULL,
	[OSVDB] [nvarchar](50) NULL,
	[PCIFAIL] [nvarchar](50) NULL,
	[PREVIOUSCYRATING] [nvarchar](50) NULL,
	[PREVIOUSEXPLOITPROBABILITY] [nvarchar](50) NULL,
	[SCRIPTCREATED] [nvarchar](50) NULL,
	[SOLUTIONPRODUCT] [nvarchar](500) NULL,
	[SOLUTIONTITLE] [nvarchar](1000) NULL,
	[SOLUTIONTYPE] [nvarchar](50) NULL,
	[VCBUG] [nvarchar](50) NULL,
	[VCCVE] [nvarchar](50) NULL,
	[VCCVSSVECTOR] [nvarchar](50) NULL,
	[VCFAM] [nvarchar](50) NULL,
	[VCNAME] [nvarchar](500) NULL,
	[WAS_FALSEPOS] [nvarchar](50) NULL,
	[WAS_INFORMATIONAL] [nvarchar](50) NULL,
	[WASC] [nvarchar](50) NULL,
	[XID] [nvarchar](50) NOT NULL,
 CONSTRAINT [XID_VulnerabilityDb] UNIQUE NONCLUSTERED 
(
	[XID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = ON, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

/****** Object:  StoredProcedure [dbo].[prcInsertFindings]    Script Date: 23/08/2022 09:38:08 ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON