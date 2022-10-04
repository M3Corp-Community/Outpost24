import json
import os
import time
from unicodedata import name
import requests
import pyodbc
import asyncio
import pandas as pd
import io
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def linha(tam = 42):
    return '-' * tam

def cabecalho(txt):
    print(linha())
    print(txt.center(42))
    print(linha())

def leiaInt(msg):
    while True:
        try:
            n = int(input(msg))
        except (ValueError, TypeError):
            print('\033[1;31mERRO: Por favor, digite uma opção válida.\033[m')
            continue
        except (KeyboardInterrupt):
            print('Usuário preferiu não digitar esta opção.')
            return 0
        else:
            return n

def menu(lista):
    cabecalho('SISTEMA INTEGRAÇÃO O24')
    c = 1
    for item in lista:
        print(f'\033[33m{c}\033[m - \033[34m{item}\033[m')
        c += 1
    print(linha())
    opc = leiaInt('Sua opção: ')
    return opc

def criaconf():
    with open(r"C:\outpost24_integration\conf.db", "w") as myfile:
        print('Informe o nome do SERVER: ')
        servidor = input()
        print('Informe o nome do banco de dados: ')
        database = input()
        print('Informe nome de usuário do banco: ')
        usuario = input()
        print('Informe a senha do banco:')
        senha = input()
        myfile.write(servidor + '\n' + database + '\n'  + usuario + '\n'  + senha)
        os.system('cls' if os.name == 'nt' else clear)
    print('Configurações criadas com sucesso!')

def settings(): 
    # Conexao na base de dados
    config = {}
    print('Lendo arquivo de conf.db')
    with open(r"C:\outpost24_integration\conf.db", "r") as myfile:
            servidor = myfile.readline().strip(" \n")
            database = myfile.readline().strip(" \n")
            usuario = myfile.readline().strip(" \n")
            senha = myfile.readline().strip(" \n")
    try:
        print('--> Conectando na base de dados:')
        conn_str = ("Driver={SQL Server Native Client 11.0};"
            "Server=%s;" 
            "Database=%s;"
            "UID=%s;"
            "PWD=%s;MARS_Connection=Yes;") % (servidor, database, usuario, senha)
        config["conn"] = pyodbc.connect(conn_str, autocommit=True)
        print('---> Conexao realizada com sucesso!')
    except:
        print('\033[1;31m-----> ERRO: conexao base de dados\033[m')
    return config

# Conexão na API para coleta da base de vulnerabilidades
def testaAPI(tenants):
    
    if (tenants["token"] == "" or tenants["host"] == ""):
        print('\033[1;31m-----> ERRO: Token nao localizado!\033[m')
        exit()
    else:
        reqs = []
        try:
            TenantID = tenants["id"]
            Name = tenants["name"]
            Host = tenants["host"]
            Token = tenants["token"]
            conncurrentRequests = 5
            TargetGroup = "-1" 
            filter = ""
            fields = ""
            limit = 5000
            page = 1
            risk_position = 0
            request = f'{Host}/opi/XMLAPI?ACTION=TARGETDATA&fields={fields}&page={page}&start={risk_position}&limit={limit}&JSON=1&REQUESTTIMEOUT=120&APPTOKEN={Token}'
            request_api = requests.get(request, verify=False)
            resultado= json.loads(request_api.text)
            resultado_api = (resultado['action'])
            print('-----> SUCESSO: Conexão API estabelecida com sucesso! | TENANT:', Name)
            return resultado 

        except:
            print('\033[1;31m-----> ERRO: Erro no teste de conexão com API\033[m', "| TENANT:", Name, '\nVerifique as informações dos tenants (Token, URL, ou se seu endereço IP está liberado para acesso a API.\n')

os.system('cls' if os.name == 'nt' else clear)

while True: 
    resposta = menu(['Criar conf do Banco', 'Testar conexão com banco','Criar tabelas no banco', 'Cadastrar Tenants', 'Testar conexão com API', 'Criar agendamento','Iniciar coleta de dados manual','sair do sistema'])
# Criar conf do banco de dados
    if resposta == 1:
        print('1 - Criar conf do Banco')
        criaconf()

        time.sleep(int(2))
        input("\nPressione <enter> para encerrar!")
        os.system('cls' if os.name == 'nt' else clear)

# Testar conexão com banco
    elif resposta == 2:
        print('2 - Testar conexão com banco')
        try:
            config = settings()
            time.sleep(int(2))
            input("\nPressione <enter> para encerrar!")
            os.system('cls' if os.name == 'nt' else clear)
        except:
            print('\033[1;31m-----> ERRO: Arquivo conf.db corrompido ou inexistente.\033[m')
            time.sleep(int(2))
            input("\nPressione <enter> para encerrar!")        
            os.system('cls' if os.name == 'nt' else clear)

# Cria tabelas e store procedures no banco de dados
    elif resposta == 3:
        print('3 - Criar tabelas no banco')
        with open(r"C:\outpost24_integration\conf.db", "r") as myfile:
            servidor = myfile.readline().strip(" \n")
            database = myfile.readline().strip(" \n")
            
        with io.open(r'C:\outpost24_integration\script_cria_table.sql', 'r', encoding = "utf-16") as inserts:
                criatable = inserts.read()
                criatable = criatable.replace('|######|', database)
        with io.open(r'C:\outpost24_integration\script_insert_data.sql', 'r', encoding = "utf-16") as inserts:
                insertdata = inserts.read()
        with io.open(r'C:\outpost24_integration\cria_proc_findings.sql', 'r', encoding = "utf-16") as inserts:
            criaproc01 = inserts.read()
        with io.open(r'C:\outpost24_integration\cria_proc_groups.sql', 'r', encoding = "utf-16") as inserts:
            criaproc02 = inserts.read()
        with io.open(r'C:\outpost24_integration\cria_proc_scanhis.sql', 'r', encoding = "utf-16") as inserts:
            criaproc03 = inserts.read()
        with io.open(r'C:\outpost24_integration\cria_proc_targets.sql', 'r', encoding = "utf-16") as inserts:
            criaproc04 = inserts.read()
        with io.open(r'C:\outpost24_integration\cria_proc_vuln.sql', 'r', encoding = "utf-16") as inserts:
            criaproc05 = inserts.read()

        config = settings()
        sql = config["conn"].cursor()
        
        try:        
            print('-----> Criando tabela:')
            sql.execute(criatable)
            sql.commit()
            print('-----> SUCESSO: Tabela criada com sucesso!')

            print('-----> Inserindo dados na tabela:')
            sql.execute(insertdata)
            sql.commit()
            print('-----> SUCESSO: Dados inseridos com sucesso!')

            print('-----> Criando Store procedure:')
            sql.execute(criaproc01)
            sql.execute(criaproc02)
            sql.execute(criaproc03)
            sql.execute(criaproc04)
            sql.execute(criaproc05)
            sql.commit()
            print('-----> SUCESSO: Store procedure criada com sucesso!')
            input("\nPressione <enter> para encerrar!")        

        except pyodbc.Error as err:
            print('\033[1;31m-----> ERRO: %s\033[m' % err)
        except:
            print('\033[1;31m-----> ERRO: Algum erro grave ocorreu!\033[m')

        time.sleep(int(5))
        input("\nPressione <enter> para encerrar!")
        os.system('cls' if os.name == 'nt' else clear)

# Cadastra dados dos tenants no banco
    elif resposta == 4:
        print('4 - Cadastrar Tenants')
        print('Informe o nome do Tenant: ')
        tenant = input()
        print('Informe o Token de API: ')
        token = input()
        print('Informe o status\n [1] Ativo \n [0] Inativo: ')
        status = input()
        print('Informe o host:')
        host = input()

        config = settings()

        sql = config["conn"].cursor()
        sql.execute('''
            INSERT INTO tenants (tenant, token, status, host)
            VALUES
            ('%s','%s',%s,'%s') 
            ''' % (tenant, token, status, host)) 
        sql.commit()

        time.sleep(int(2))
        input("\nPressione <enter> para encerrar!")        
        os.system('cls' if os.name == 'nt' else clear)

# Valida conexão com Tenants
    elif resposta == 5:
        print('5 - Testar conexão com API')
        config = settings()

        # Loop Tentants:
        print('---> Looping tentants:')
        sql = config["conn"].cursor()
        sql.execute('select * from tenants where status = 1 order by id asc')
        for i in sql:
            tenants = {}
            tenants["id"] = i[0]
            tenants["name"] = i[1]
            tenants["token"] = i[2]
            tenants["status"] = i[3]
            tenants["host"] = i[4]

            print('----> Conectando na API:')
            testaAPI(tenants)

        time.sleep(int(4))
        input("\nPressione <enter> para encerrar!")        
        os.system('cls' if os.name == 'nt' else clear)

# Cria agendamento para coleta de dados
    elif resposta == 6:
        print('6 - Criar agendamento')
        print('Informe o horario para o agendamento [hh:mm]: ')
        hora = input()
        os.system(r'SCHTASKS /Create /SC DAILY /TN integracaoO24 /TR C:\outpost24_integration\api_o24.py /ST ' + hora)
        time.sleep(int(2))
        input("\nPressione <enter> para encerrar!")        
        os.system('cls' if os.name == 'nt' else clear)

# Inicia a coleta de dados manual
    elif resposta == 7:
        print('7 - Coletar dados manualmente')
        exec(open(r'C:\outpost24_integration\api_o24.py', 'r').read())

        time.sleep(int(2))
        input("\nPressione <enter> para encerrar!")        
        os.system('cls' if os.name == 'nt' else clear)

# Saindo do sistema
    elif resposta == 8:
        print('Saindo do sistema...')
        break
    
# Mensagem de erro
    else:
        print('\033[1;31mERRO! Digite uma opção válida!\033[m')
        time.sleep(int(2))
        input("\nPressione <enter> para encerrar!")
        os.system('cls' if os.name == 'nt' else clear)

