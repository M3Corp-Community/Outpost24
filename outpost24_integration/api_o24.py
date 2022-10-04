from dataclasses import fields
import requests
import pandas as pd
from pandas.io.json import json_normalize
from pandas import ExcelWriter
import openpyxl
import os
import json
import time
import aiohttp
import asyncio
import datetime as datetime
import pyodbc
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# Desativa warnings na execucao
import warnings
warnings.filterwarnings('ignore')



def settings():
    # Define configuracoes 
    config = {}
    config["hiab"] = "https://outscan.outpost24.com" 
    print('Lendo arquivo de conf.db')
    with open(r"C:\outpost24_integration\conf.db", "r") as myfile:
            servidor = myfile.readline().strip(" \n")
            database = myfile.readline().strip(" \n")
            usuario = myfile.readline().strip(" \n")
            senha = myfile.readline().strip(" \n")


    # Conexao na base de dados
    print('--> Conectando na base de dados:')
    try:
        print('--> Conectando na base de dados:')
        conn_str = ("Driver={SQL Server Native Client 11.0};"
            "Server=%s;" 
            "Database=%s;"
            "UID=%s;"
            "PWD=%s;MARS_Connection=Yes;") % (servidor, database, usuario, senha)
        config["conn"] = pyodbc.connect(conn_str, autocommit=True)
        print('---> Conexao realizada com sucesso!')
        print(database)
    except:
        print('-----> ERRO: conexao base de dados')
 
    return config


async def downloadData(session, apiCall, concurrentrequestlimit):
    async with concurrentrequestlimit, session.get(apiCall) as response:
        return await response.text()

# Conexão na API para coleta de Findings=
async def findings(config, tenants):
    print('----> Iniciando coleta dados tenant: ', tenants["name"])
    
    if (tenants["token"] == "" or tenants["host"] == ""):
        print('-----> ERRO: Token nao localizado!')
        exit()
    else:
        reqs = []
        try:
            TenantID = tenants["id"]
            Host = tenants["host"]
            Token = tenants["token"]
            conncurrentRequests = 5
            TargetGroup = "-1" 
            filter = ""
            fields = ""
            limit = 5000
            page = 1
            risk_position = 0
            request = f'{Host}/opi/XMLAPI?ACTION=REPORTTARGETDATA&REQUESTTIMEOUT=300&FETCHGROUPS=0&fields={fields}&offset=0&TARGETS=-1&TARGETGROUPS="{TargetGroup}"&SCANLOGXID=&SCHEDULEXID=&GROUPS={TargetGroup}&JSON=1&COLLAPSED=&{filter}&page=1&start=0&limit=1&APPTOKEN={Token}'
            Max_Risks_Request = requests.get(request, verify=False)
            Max_Risks_Response = json.loads(Max_Risks_Request.text)
            Risk_limit = int(Max_Risks_Response['totalcount'])
            page = page + 1
            risk_position = risk_position + 1
            print('-----> Numero de findings detectados: ', Risk_limit)

            while risk_position <= Risk_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=REPORTTARGETDATA&REQUESTTIMEOUT=300&FETCHGROUPS=0&fields={fields}&offset=0&TARGETS=-1&TARGETGROUPS={TargetGroup}&SCANLOGXID=&SCHEDULEXID=&GROUPS={TargetGroup}&JSON=1&COLLAPSED=&{filter}&page={page}&start={risk_position}&limit={limit}&APPTOKEN={Token}')
                page = page + 1
                risk_position = risk_position + limit
            print(f'-----> Total requisicoes a serem executadas: {len(reqs)}')
            
            apiResponses = []
            concurrentrequestlimit = asyncio.BoundedSemaphore(value=conncurrentRequests)
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                
                for apiCall in reqs:
                    apiResponses.append(downloadData(session,apiCall,concurrentrequestlimit))
                downloadedData = await asyncio.gather(*apiResponses)
                
                for data in downloadedData:
                    jsonData = json.loads(data)
                    for key in jsonData['data']:
                        key['tenant_id'] = TenantID
                    json_findings = jsonData['data']
                    json_string = json.dumps(json_findings)
                    #print(json_string)
                    #exit()
                
                    try:        
                        #print(json_string) ## Exibir o JSON localizado
                        sql = config["conn"].cursor()
                        proc = "EXEC prcInsertFindings @json = ?"
                        sql.execute(proc, json_string)
                        sql.close()
 
                        print('-----> SUCESSO: Dados gravados com sucesso na base de dados!')
                    except pyodbc.Error as err:
                        print('-----> ERRO: %s' % err)
                    except:
                        print('-----> ERRO: Algum erro grave ocorreu!')
    
                return 
             
        except:
            print('-----> ERRO: Erro na chamada a API busca findings')
            exit()

# Conexão na API para coleta da base de vulnerabilidades
async def vulnerability_database(config, tenants):
    
    if (tenants["token"] == "" or tenants["host"] == ""):
        print('-----> ERRO: Token nao localizado!')
        exit()
    else:
        reqs = []
        try:
            TenantID = tenants["id"]
            Host = tenants["host"]
            Token = tenants["token"]
            conncurrentRequests = 5
            TargetGroup = "-1" 
            filter = ""
            fields = ""
            limit = 5000
            page = 1
            risk_position = 0
            request = f'{Host}/opi/XMLAPI?ACTION=SCRIPTDATA&fields={fields}&page={page}&start={risk_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}'
            Max_Risks_Request = requests.get(request, verify=False)
            Max_Risks_Response = json.loads(Max_Risks_Request.text)
            Risk_limit = int(Max_Risks_Response['totalcount'])
            VulnDbTable = pd.DataFrame(Max_Risks_Response['data'])
            page = page + 1
            risk_position = risk_position + 1
            print('-----> Total vulnerabilidades detectados na base: ', Risk_limit)

            print("Generating Request Bundle")
            while risk_position <= Risk_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=SCRIPTDATA&fields={fields}&page={page}&start={risk_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                risk_position = risk_position + limit
            print(f'Total Requests to run {len(reqs)}')

            while risk_position <= Risk_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=SCRIPTDATA&fields={fields}&page={page}&start={risk_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                risk_position = risk_position + limit
            print(f'-----> Total requisicoes a serem executadas: {len(reqs)}')
            
            apiResponses = []
            concurrentrequestlimit = asyncio.BoundedSemaphore(value=conncurrentRequests)
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                
                for apiCall in reqs:
                    apiResponses.append(downloadData(session,apiCall,concurrentrequestlimit))
                downloadedData = await asyncio.gather(*apiResponses)
                
                print('-----> Executando StoreProcedure base vulnerabilidades:')
                for data in downloadedData:
                    jsonData = json.loads(data)
                    json_findings = jsonData['data']
                    json_string = json.dumps(json_findings)

                    try:        
                        #print(json_string) ## Exibir o JSON localizado
                        sql = config["conn"].cursor()
                        proc = "EXEC prcInsertVulnerability @json = ?"
                        sql.execute(proc, json_string)
                        sql.close()
 
                    except pyodbc.Error as err:
                        print('-----> ERRO: %s' % err)
                    except:
                        print('-----> ERRO: Algum erro grave ocorreu!')

                    
        except:
            print('-----> ERRO: Erro na chamada a API busca vulnerabilidades')
            exit()

# Conexão na API para coleta de Targets
async def targets_database(config, tenants):
    
    if (tenants["token"] == "" or tenants["host"] == ""):
        print('-----> ERRO: Token nao localizado!')
        exit()
    else:
        reqs = []
        try:
            TenantID = tenants["id"]
            Host = tenants["host"]
            Token = tenants["token"]
            conncurrentRequests = 5
            TargetGroup = "-1" 
            filter = ""
            fields = ""
            limit = 5000
            page = 1
            target_position = 0
            request = f'{Host}/opi/XMLAPI?ACTION=TARGETDATA&fields={fields}&page={page}&start={target_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}'
            Max_targets_Request = requests.get(request, verify=False)
            Max_targets_Response = json.loads(Max_targets_Request.text)
            target_limit = int(Max_targets_Response['totalcount'])
            VulnDbTable = pd.DataFrame(Max_targets_Response['data'])
            page = page + 1
            target_position = target_position + 1
            print('-----> Total TARGETS detectados na base: ', target_limit)

            print("Generating Request Bundle")
            while target_position <= target_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=TARGETDATA&fields={fields}&page={page}&start={target_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                target_position = target_position + limit
            print(f'Total Requests to run {len(reqs)}')

            while target_position <= target_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=TARGETDATA&fields={fields}&page={page}&start={target_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                target_position = target_position + limit
            print(f'-----> Total requisicoes a serem executadas: {len(reqs)}')
            
            apiResponses = []
            concurrentrequestlimit = asyncio.BoundedSemaphore(value=conncurrentRequests)
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                
                for apiCall in reqs:
                    apiResponses.append(downloadData(session,apiCall,concurrentrequestlimit))
                downloadedData = await asyncio.gather(*apiResponses)
                
                for data in downloadedData:
                    jsonData = json.loads(data)
                    json_findings = jsonData['data']
                    json_string = json.dumps(json_findings)

                    try:        
                        #print(json_string) ## Exibir o JSON localizado
                        print('-----> Executando StoreProcedure base targets:')
                        sql = config["conn"].cursor()
                        proc = "EXEC prcInsertTargets @json = ?"
                        sql.execute(proc, json_string)
                        sql.close()
 
                        print('-----> SUCESSO: Dados gravados com sucesso na base de dados!')
                    except pyodbc.Error as err:
                        print('-----> ERRO: %s' % err)
                    except:
                        print('-----> ERRO: Algum erro grave ocorreu!')
               
        except:
            print('-----> ERRO: Erro na chamada a API busca targets')
            exit()


# Conexão na API para coleta de Grupos
async def groups_database(config, tenants):
    
    if (tenants["token"] == "" or tenants["host"] == ""):
        print('-----> ERRO: Token nao localizado!')
        exit()
    else:
        reqs = []
        try:
            TenantID = tenants["id"]
            Host = tenants["host"]
            Token = tenants["token"]
            conncurrentRequests = 5
            TargetGroup = "-1" 
            filter = ""
            fields = ""
            limit = 5000
            page = 1
            group_position = 0
            request = f'{Host}/opi/XMLAPI?ACTION=TARGETGROUPDATA&fields={fields}&page={page}&start={group_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}'
            Max_groups_Request = requests.get(request, verify=False)
            Max_groups_Response = json.loads(Max_groups_Request.text)
            group_limit = int(Max_groups_Response['totalcount'])
            VulnDbTable = pd.DataFrame(Max_groups_Response['data'])
            page = page + 1
            group_position = group_position + 1
            print('-----> Total Grupos detectados na base: ', group_limit)

            print("Generating Request Bundle")
            while group_position <= group_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=TARGETGROUPDATA&fields={fields}&page={page}&start={group_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                group_position = group_position + limit
            print(f'Total Requests to run {len(reqs)}')

            while group_position <= group_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=TARGETGROUPDATA&fields={fields}&page={page}&start={group_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                group_position = group_position + limit
            print(f'-----> Total requisicoes a serem executadas: {len(reqs)}') 
            
            apiResponses = []
            concurrentrequestlimit = asyncio.BoundedSemaphore(value=conncurrentRequests)
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                
                for apiCall in reqs:
                    apiResponses.append(downloadData(session,apiCall,concurrentrequestlimit))
                downloadedData = await asyncio.gather(*apiResponses)
                
                for data in downloadedData:
                    jsonData = json.loads(data)
                    json_findings = jsonData['data']
                    json_string = json.dumps(json_findings)

                    try:        
                        #print(json_string) ## Exibir o JSON localizado
                        print('-----> Executando StoreProcedure base Groups:')
                        sql = config["conn"].cursor()
                        proc = "EXEC prcInsertGroups @json = ?"
                        sql.execute(proc, json_string)
                        sql.close()
 
                        print('-----> SUCESSO: Dados gravados com sucesso na base de dados!')
                    except pyodbc.Error as err:
                        print('-----> ERRO: %s' % err)
                    except:
                        print('-----> ERRO: Algum erro grave ocorreu!')
               
        except:
            print('-----> ERRO: Erro na chamada a API busca Groups')
            exit()

# Conexão na API para coleta de Scan History
async def scanhis_database(config, tenants):
    
    if (tenants["token"] == "" or tenants["host"] == ""):
        print('-----> ERRO: Token nao localizado!')
        exit()
    else:
        reqs = []
        try:
            TenantID = tenants["id"]
            Host = tenants["host"]
            Token = tenants["token"]
            conncurrentRequests = 5
            TargetGroup = "-1" 
            filter = ""
            fields = ""
            limit = 5000
            page = 1
            scan_position = 0
            request = f'{Host}/opi/XMLAPI?ACTION=SCANLOG&fields={fields}&page={page}&start={scan_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}'
            Max_scans_Request = requests.get(request, verify=False)
            Max_scans_Response = json.loads(Max_scans_Request.text)
            scan_limit = int(Max_scans_Response['totalcount'])
            VulnDbTable = pd.DataFrame(Max_scans_Response['data'])
            page = page + 1
            scan_position = scan_position + 1
            print('-----> Total Grupos detectados na base: ', scan_limit)

            print("Generating Request Bundle")
            while scan_position <= scan_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=SCANLOG&fields={fields}&page={page}&start={scan_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                scan_position = scan_position + limit
            print(f'Total Requests to run {len(reqs)}')

            while scan_position <= scan_limit:
                reqs.append(f'{Host}/opi/XMLAPI?ACTION=SCANLOG&fields={fields}&page={page}&start={scan_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}')
                page = page + 1
                scan_position = scan_position + limit
            print(f'-----> Total requisicoes a serem executadas: {len(reqs)}') 
            
            apiResponses = []
            concurrentrequestlimit = asyncio.BoundedSemaphore(value=conncurrentRequests)
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                
                for apiCall in reqs:
                    apiResponses.append(downloadData(session,apiCall,concurrentrequestlimit))
                downloadedData = await asyncio.gather(*apiResponses)
                
                for data in downloadedData:
                    jsonData = json.loads(data)
                    json_findings = jsonData['data']
                    json_string = json.dumps(json_findings)

                    try:        
                        #print(json_string) ## Exibir o JSON localizado
                        print('-----> Executando StoreProcedure base Scan History:')
                        sql = config["conn"].cursor()
                        proc = "EXEC prcInsertScanHistory @json = ?"
                        sql.execute(proc, json_string)
                        sql.close()
 
                        print('-----> SUCESSO: Dados gravados com sucesso na base de dados!')
                    except pyodbc.Error as err:
                        print('-----> ERRO: %s' % err)
                    except:
                        print('-----> ERRO: Algum erro grave ocorreu!')
               
        except:
            print('-----> ERRO: Erro na chamada a API busca Groups')
            exit()

#Iniciando Processo
start_time = time.time()
print(f'-> Iniciando Processo: {datetime.datetime.now()}')
config = settings()

# Loop Tentants:
print('---> Looping tentants:')
sql = config["conn"].cursor()
sql.execute('select * from tenants where status = 1 order by id asc')
vuln_check = 0
for i in sql:
    tenants = {}
    tenants["id"] = i[0]
    tenants["name"] = i[1]
    tenants["token"] = i[2]
    tenants["status"] = i[3]
    tenants["host"] = i[4]

    # Coleta base de vulnerabilidades
    if vuln_check == 0:
        print('----> Atualizando base de vulnerabilidades:')
        vuln_check = 1
        loop = asyncio.get_event_loop()
        loop.run_until_complete(vulnerability_database(config, tenants))
        print('-----> SUCESSO: Dados gravados com sucesso na base de dados!')
        

    # Executa rotina coleta findings
    loop = asyncio.get_event_loop()
    loop.run_until_complete(findings(config, tenants))

    # Executa rotina coleta targets
    loop = asyncio.get_event_loop()
    loop.run_until_complete(targets_database(config, tenants))

    # Executa rotina coleta targets
    loop = asyncio.get_event_loop()
    loop.run_until_complete(groups_database(config, tenants))

    # Executa rotina coleta targets
    loop = asyncio.get_event_loop()
    loop.run_until_complete(scanhis_database(config, tenants))

config["conn"].close()
print(f'-> Finalizando Processo: {datetime.datetime.now()}')


