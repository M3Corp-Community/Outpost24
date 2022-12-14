USE outpost24_integration

-- Insert da tabela Appendix B - Schedule Frequency Table

INSERT INTO ScheduleFreqTable
(SCHEDULE_CODE, FREQUENCY)
VALUES 
    (1, 'Weekly'),
    (2, 'Monthly'),
    (3, 'Quarterly'),
    (4, 'Fortnightly'),
    (5, 'Daily'),
    (6, 'Bimonthly'),
    (10, 'Once');


-- Insert da tabela Appendix C - Scan Status Table
USE outpost24_integration

INSERT INTO ScanStatusTable
(SCANSTATUSCODE, DESCRIPTION)
VALUES 
    (-1, 'Not scanned'),
    (0, 'Completed (Scheduled)'),
    (1, 'Completed (Forced)'),
    (2, 'Timeout'),
    (3, 'Stopped'),
    (4, 'Stopped (By user)'),
    (5, 'Large report'),
    (6, 'Stopped (Large report)'),
    (7, 'Failed'),
    (8, 'Scan window paused'),
    (9, 'Scan window resume'),
    (11, 'Discovery - Scan running'),
    (12, 'Discovery - Done'),
    (13, 'Discovery -Time out'),
    (14, 'Discovery -Stopped'),
    (18, 'Schedule job not started'),
    (19, 'Schedule job currently running'),
    (20, 'Schedule job done'),
    (22, 'Schedule job failed'),
    (30, 'HIAB update'),
    (31, 'HIAB script update'),
    (32, 'HIAB backup'),
    (33, 'HIAB import'),
    (34, 'HIAB synchronize');

-- Insert da tabela Appendix D - Error Codes
USE outpost24_integration

INSERT INTO ErrorCodes
(ERROR, MESSAGE, EXTENDED_EXPLANATION)
VALUES 
    (100, 'You are not logged in.', 'The action you have requested require that you are logged into the system.'),
    (101, 'Access is denied.',	'You don''t have access to perform the requested function.'),
    (102, 'Incorrect login.',	'You have supplied the wrong credentials.'),
    (103, 'No records where removed.',	'You tried to remove something from the system but no records where removed during the request.'),
    (104, 'All required fields are not present.',	'All fields which are required in order to perform the request has not been supplied correctly.'),
    (105, 'The account you are trying to update does not exist.',	'The account you tried to update does not exist.'),
    (106, 'No targets found to be updated.',	'The target you tried to update does not exist.'),
    (107, 'The country code is invalid.',	'The supplied country code is not valid.'),
    (108, 'The mobile number is invalid.',	'The format of the mobile number is incorrect.'),
    (109, 'Username must be greater then four characters.',	'The minimum length of the user name id four characters.'),
    (110, 'The username is taken by another user.',	'The selected user name is not available.'),
    (111, 'Password must be greater then five characters.',	'Password must contain at least six characters.'),
    (112, 'Too many login attempts. The account is locked.',	'You have given the wrong password credentials to many times and the account has been locked. In order to gain access again you need to perform a Forgot login.'),
    (113, 'Old password is incorrect.',	'When you tried to change passwords you supplied the wrong old password.'),
    (114, '<Not used>',	''),
    (115, 'To many entries defined. The maximum is:',	'You are trying to add more than allowed. The error message will state how many entries that are allowed.'),
    (116, 'Unsupported value in field.',	'The mentioned field contains unsupported values.'),
    (117, 'No test was sent. Failed to find receiver.',	'This occurs if the user tries to send a test message and we are unable to determine the receiver.'),
    (118, 'Vaildation of input failed.',	'Something in the request isn''t vaild.'),
    (119, '<Not used>',	''),
    (120, 'Invalid email address.',	'The email address isn''t valid.'),
    (121, 'Parameter to low:',	'The mentioned parameter is to low.'),
    (122, 'Parameter to high:',	'The mentioned parameter is to high.'),
    (123, 'Importing data. Please try again later.',	'An import is being done, system will be disabled during that period.'),
    (124, 'Logged out due to inactivity.',	'The account has been logged out due to inactivity.'),
    (500, 'Internal server error.',	'When handling the request somethin unexpected occured which terminated the request.'),
    (998, 'Database not in UTF-8. Localization disabled. Contact support.',	'The database is missing a significant patch, please contact support for further assistance.'),
    (999, 'Server is not registered.',	'The HIAB appliance is not registered to an account on Outpost24, please contact support for further instructions.');


-- Insert da tabela Appendix H - Audit Applications
USE outpost24_integration

INSERT INTO AuditAplications
(VALUE, DESCRIPTION)
VALUES 
    ('tHiab',	'HIAB changes'),
    ('tMonitorHostS',	'Monitor log'),
    ('tOutscanFileS',	'Uploaded files'),
    ('tPdetectS',	'Discovery scans'),
    ('tReportS',	'Report generation'),
    ('tReportTextS',	'Report text modifications'),
    ('tReport_DisputeS',	'PCI Disputes'),
    ('tSavedscanprefS',	'Scan policies'),
    ('tScannerS',	'Distributed scan changes'),
    ('tScheduleObjectS',	'Schedules'),
    ('tSubUserS',	'Sub account'),
    ('tUserGroupS',	'Groups'),
    ('tUserDataS',	'Targets'),
    ('tWorkflowS',	'Tickets');

-- Insert da tabela Appendix I - Report Types
USE outpost24_integration

INSERT INTO ReportTypes
(TYPE, DESCRIPTION)
VALUES 
    (0,	'Summary'),
    (2,	'Executed scripts'),
    (3,	'Detailed'),
    (4,	'Trend summary'),
    (5,	'Trend detailed'),
    (7,	'Group summary'),
    (8,	'Delta report'),
    (9,	'Solution report'),
    (10,	'PCI summary'),
    (11,	'PCI detailed');

-- Insert da tabela Appendix I - Report Types
USE outpost24_integration

INSERT INTO RiskTable
(RISK, DESCRIPTION)
VALUES 
    (0,	'Information'),
    (1,	'Low risk'),
    (2,	'Medium risk'),
    (4,	'High risk');


-- Insert da tabela Appendix N - Event Type
USE outpost24_integration

INSERT INTO EventType
(TYPE, DESCRIPTION)
VALUES 
    (0,	'Finding - Information'),
    (1,	'Finding - Low risk'),
    (2,	'Finding - Medium risk'),
    (4,	'Finding - High risk'),
    (5,	'Scan results ready'),
    (6,	'Large report detected'),
    (7,	'Scan started'),
    (8,	'Scan timeout'),
    (9, 'Scan stopped'),
    (10, 'Scan failed'),
    (11, 'Network monitor - Open port'),
    (12, 'Network monitor - Closed port'),
    (13, 'Network monitor - Answer on ping'),
    (14, 'Network monitor - No answer on ping'),
    (15, 'HIAB update'),
    (16, 'HIAB boot'),
    (18, 'HIAB backup'),
    (19, 'System restarted'),
    (20, 'Discovery - Notification'),
    (21, 'Discovery - Alive host'),
    (22, 'Discovery - Dead host'),
    (23, 'Discovery - Host added to system'),
    (24, 'Target added to system'),
    (25, 'Target removed from system'),
    (26, 'Scan notification'),
    (30, 'User login notification'),
    (31, 'Scanner missing'),
    (32, 'Maintenance plan completed'),
    (33, 'Update failed'),
    (34, 'Verify done'),
    (35, 'Scan - Not reachable'),
    (36, 'Scan - Updated'),
    (37, 'Backup failed'),
    (38, 'Release notes'),
    (39, 'Scan: Could not start SLS'),
    (40, 'Scan: Schedule started');

-- Insert da tabela Appendix I - Report Types
USE outpost24_integration

INSERT INTO Solutiontype
(TYPE, DESCRIPTION)
VALUES 
    (0,	'Unspecified'),
    (1,	'Unknown'),
    (2,	'Reconfigure (software)'),
    (3,	'Workaround'),
    (4,	'InProgress (solution is being investigated)'),
    (5,	'Contact vendor'),
    (6,	'Update (software)'),
    (7,	'Patch (software)'),
    (8,	'Unack (Unacknowledged solution by vendor)'),
    (9,	'NoSol (No known solution)'),
    (10,	'Account (change account settings)'),
    (11,	'Disable (the service)'),
    (11,	'Filter (access)'),
    (13,	'Malware');