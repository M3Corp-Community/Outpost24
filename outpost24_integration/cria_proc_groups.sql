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