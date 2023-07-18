try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from datetime import datetime
    import time
    import os
    import shutil
    import json
    import logging
    import subprocess
    import base64

    #função de descriptografação de byte para string
    def aes_decrypt(key, ciphertext, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

        return plaintext

    #conferindo data e hora
    now = datetime.now()

    #abrindo log em um txt
    nome_txt = "log_dia_" + now.strftime('%d') + "." + now.strftime('%m') + "." + now.strftime('%Y') + ".txt"

    #abrindo json
    with open("C:\\Users\\moraesg\\Desktop\\test_credentials\\nomes.json", "r", encoding="utf-8-sig") as arquivo:
        var = arquivo.read()
    #setando os objetos dentro do json como valor_json[]
    valor_json = json.loads(var)

    #desencriptando os caminhos nos servers, usuários e senhas de entro do json =======================================================================================================================
    pasta_txt = valor_json ["pasta_txt"]
    trash_folder = valor_json["lixo"]
    tempo_pausa = valor_json ["tempo_pausa"]


    key = base64.b64decode(valor_json['key'].encode('utf-8'))
    iv = base64.b64decode(valor_json['iv'].encode('utf-8')) 

    # IMPORTANTE IMPORTANTE - source username e source password servem para o source_folder e o arquive_folder pois estão no mesmo caminho
    arquive_folder_uncripted = base64.b64decode(valor_json['arquive_folder'].encode('utf-8'))
    source_folder_uncripted = base64.b64decode(valor_json['source_folder'].encode('utf-8'))
    source_username_uncripted = base64.b64decode(valor_json['source_username'].encode('utf-8'))
    source_password_uncripted = base64.b64decode(valor_json['source_password'].encode('utf-8')) 

    destination_folder_uncripted = base64.b64decode(valor_json['dest_folder'].encode('utf-8'))
    dest_username_uncripted = base64.b64decode(valor_json['dest_username'].encode('utf-8'))
    dest_password_uncripted = base64.b64decode(valor_json['dest_password'].encode('utf-8')) 

    #descriptografando de bytes para string =============================================================================================================================================================================
    pasta_arquivo =  aes_decrypt(key, arquive_folder_uncripted, iv)
    arquive_folder = pasta_arquivo.decode('utf-8')

    pasta_raiz = aes_decrypt(key, source_folder_uncripted, iv)
    source_folder = pasta_raiz.decode('utf-8')

    senha_raiz = aes_decrypt(key, source_password_uncripted, iv)
    source_password = senha_raiz.decode('utf-8')

    usuario_raiz = aes_decrypt(key, source_username_uncripted, iv)
    source_username = usuario_raiz.decode('utf-8')

    pasta_destino = aes_decrypt(key, destination_folder_uncripted, iv)
    destination_folder = pasta_destino.decode('utf-8')

    senha_destino = aes_decrypt(key, dest_password_uncripted, iv)
    dest_password = senha_destino.decode('utf-8')

    usuario_destino = aes_decrypt(key, dest_username_uncripted, iv)
    dest_username = usuario_destino.decode('utf-8')




    print("pending : ", source_folder, " arquive : ", arquive_folder)

    #fim da descriptografação
    def mover_arquivos(arquive_folder, source_folder, destination_folder, source_password, dest_password, source_username, dest_username):
        try:
            f = open(r"C:\Users\moraesg\Desktop\test_credentials" + nome_txt, "a+")
            conexao_raiz = subprocess.run(['net', 'use', source_folder, '/user:' + source_username, source_password])
            conexao_arquivo = subprocess.run(['net', 'use', arquive_folder, '/user:' + source_username, source_password])
            conexao_destino = subprocess.run(['net', 'use', destination_folder, '/user:' + dest_username, dest_password])
            
            
            files_copied = False
            
            for file_name in os.listdir(source_folder):
                now = datetime.now()
                noww = now.strftime('%d/%m/%Y %H:%M:%S')
                if 'ORD_' in file_name or 'PART_' in file_name or 'CLI_' in file_name or 'BOL_' in file_name or 'NFD_' in file_name or 'COA_' in file_name or 'NFX_' in file_name:
                    
                    command1 = ["robocopy", source_folder, destination_folder, file_name, '/MOV', '/IS']
                    command2 = ["robocopy", destination_folder, arquive_folder, file_name, '/IS']
                    
                    
                    
                    subprocess.run(command1, shell=True)
                    f.writelines("Arquivo  " + file_name + " - MOVIDO - " + noww + "\n")
                    
                    subprocess.run(command2, shell=True)
                    f.writelines("Arquivo  " + file_name + " - COPIADO - " + noww + "\n")
                    files_copied = True  
                    
                else:
                    f.writelines("Arquivo não compativel - ", noww , "\n")
                    pass
        
            
            if not files_copied:
                
                f.writelines("Nenhum arquivo presente na pasta - ", noww , "\n")
                return
        
        except Exception as e:
            f.writelines("Erro -  " + str(e) + noww + "\n")
        
    mover_arquivos(arquive_folder, source_folder, destination_folder, source_password, dest_password, source_username, dest_username) 
except Exception as e:
    import sys
    import time
    now = datetime.now()
    noww = now.strftime('%d/%m/%Y %H:%M:%S')
    f = open("ocorreu um erro.txt", "a+")
    f.writelines("ocorreu os seguinte erro : " + str(e) + noww + "\n")