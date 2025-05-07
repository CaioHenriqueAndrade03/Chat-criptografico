import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# ==== Tela ====
janela = tk.Tk()
janela.title("Chat Criptografado")
janela.withdraw()


nome_usuario = simpledialog.askstring("Login", "Digite seu nome:", parent=janela)
if not nome_usuario:
    nome_usuario = f"Usuário_{get_random_bytes(2).hex()}"

janela.deiconify()
janela.title(f"Chat Criptografado - {nome_usuario}")

chat_area = scrolledtext.ScrolledText(janela)
chat_area.pack(fill=tk.BOTH, expand=True)
chat_area.config(state='disabled')

entrada_frame = tk.Frame(janela)
entrada_frame.pack(fill=tk.X)

entrada_msg = tk.Entry(entrada_frame)
entrada_msg.pack(side=tk.LEFT, fill=tk.X, expand=True)

# ======== Conexão ==========
try:
    # Socket
    host = '127.0.0.1'
    port = 12345
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.connect((host, port))

    data = cliente.recv(4096)
    chave_publica_servidor = RSA.import_key(data)
    cifra_rsa = PKCS1_OAEP.new(chave_publica_servidor)


    chave_aes = get_random_bytes(16)  


    chave_aes_cifrada = cifra_rsa.encrypt(chave_aes)
    cliente.send(base64.b64encode(chave_aes_cifrada))

    iv = get_random_bytes(16)
    cifra_aes = AES.new(chave_aes, AES.MODE_CBC, iv)
    nome_cifrado = cifra_aes.encrypt(pad(nome_usuario.encode(), AES.block_size))
    cliente.send(base64.b64encode(iv + nome_cifrado))

    def adicionar_mensagem(mensagem):
        chat_area.config(state='normal')
        chat_area.insert(tk.END, f"{mensagem}\n")
        chat_area.config(state='disabled')
        chat_area.yview(tk.END)

    adicionar_mensagem("Conectado ao servidor!")

    def enviar_msg():
        texto = entrada_msg.get()
        if not texto:
            return
        entrada_msg.delete(0, tk.END)


        try:
            iv = get_random_bytes(16)
            cifra_aes = AES.new(chave_aes, AES.MODE_CBC, iv)
            msg_cifrada = cifra_aes.encrypt(pad(texto.encode(), AES.block_size))

            cliente.send(base64.b64encode(iv + msg_cifrada))

            adicionar_mensagem(f"(Você): {texto}")
        except Exception as e:
            adicionar_mensagem(f"Erro ao enviar: {e}")

    def receber():
        while True:
            try:
                msg_cifrada = cliente.recv(4096)
                if not msg_cifrada:
                    adicionar_mensagem("Desconectado do servidor")
                    break
                
                msg_cifrada = base64.b64decode(msg_cifrada)
                iv = msg_cifrada[:16]
                cifra_aes = AES.new(chave_aes, AES.MODE_CBC, iv)
                mensagem = unpad(cifra_aes.decrypt(msg_cifrada[16:]), AES.block_size).decode()

                adicionar_mensagem(mensagem)
            except Exception as e:
                adicionar_mensagem(f"Erro na recepção: {e}")
                break

    threading.Thread(target=receber, daemon=True).start()


    botao = tk.Button(entrada_frame, text="Enviar", command=enviar_msg)
    botao.pack(side=tk.RIGHT)

    entrada_msg.bind("<Return>", lambda event: enviar_msg())

except Exception as e:
    if not janela.winfo_exists():
        print(f"Erro de conexão: {e}")
    else:
        tk.messagebox.showerror("Erro", f"Não foi possível conectar ao servidor: {e}")
        janela.destroy()

def ao_fechar():
    try:
        cliente.close()
    except:
        pass
    janela.destroy()

janela.protocol("WM_DELETE_WINDOW", ao_fechar)
janela.mainloop()