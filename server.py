import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

clientes = {}

chave_privada = RSA.generate(2048)
chave_publica = chave_privada.publickey()

def broadcast(mensagem, origem=None):
    for conn, (nome, chave_aes) in clientes.items():
        if conn != origem: 
            try:
                iv = get_random_bytes(16)
                cifra = AES.new(chave_aes, AES.MODE_CBC, iv)
                mensagem_cifrada = cifra.encrypt(pad(mensagem.encode(), AES.block_size))
                
                pacote = base64.b64encode(iv + mensagem_cifrada)
                conn.send(pacote)
            except Exception as e:
                print(f"Erro ao enviar para {nome}: {e}")

def lidar_com_cliente(conn, addr):
    print(f"Conexão de {addr}")
    
    decifrador_rsa = PKCS1_OAEP.new(chave_privada)
    
    try:
        conn.send(chave_publica.export_key())
        
        chave_aes_cifrada = conn.recv(4096)
        chave_aes = decifrador_rsa.decrypt(base64.b64decode(chave_aes_cifrada))
        
        nome_cifrado = conn.recv(4096)
        nome_cifrado = base64.b64decode(nome_cifrado)
        iv = nome_cifrado[:16]
        cifra_aes = AES.new(chave_aes, AES.MODE_CBC, iv)
        nome = unpad(cifra_aes.decrypt(nome_cifrado[16:]), AES.block_size).decode()
        
        clientes[conn] = (nome, chave_aes)
        
        mensagem_conexao = f"({nome}) conectado"
        print(mensagem_conexao)
        broadcast(mensagem_conexao, conn)
        
        while True:
            msg_cifrada = conn.recv(4096)
            if not msg_cifrada:
                break
                
            msg_cifrada = base64.b64decode(msg_cifrada)
            iv = msg_cifrada[:16]
            cifra_aes = AES.new(chave_aes, AES.MODE_CBC, iv)
            texto = unpad(cifra_aes.decrypt(msg_cifrada[16:]), AES.block_size).decode()
            
            mensagem_completa = f"({nome}): {texto}"
            print(mensagem_completa)
            
            broadcast(mensagem_completa, conn)
            
    except Exception as e:
        print(f"Erro com {addr}: {e}")
    finally:
        if conn in clientes:
            nome_desconectado = clientes[conn][0]
            del clientes[conn]
            broadcast(f"({nome_desconectado}) desconectado")
        conn.close()

# ======= Servidor ======
host = '127.0.0.1'
port = 12345

servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
servidor.bind((host, port))
servidor.listen()

print(f"Servidor rodando em {host}:{port}")

while True:
    conn, addr = servidor.accept()
    thread = threading.Thread(target=lidar_com_cliente, args=(conn, addr))
    thread.start()