import os
import io
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import *
from BiConn import BiConn
from Auxs import hashs, mac, kdf


# seleciona-se um dos vários algorimos implementados na package
default_algorithm = hashes.SHA256

nonce_list = list()


# Gerar um nonce
def get_nonce(b):

    nonce = os.urandom(b)

    while nonce in nonce_list:
        nonce = os.urandom(b)
    nonce_list.append(nonce)

    return nonce


def my_mac(key):
    return hmac.HMAC(key, default_algorithm(), default_backend())


default_curve = ec.SECP256R1  # curva


def ECDH(conn):
    # agreement
    pk = ec.generate_private_key(default_curve, default_backend())  # ao gerar a chave privada,
    pub = pk.public_key().public_bytes(  # recebe como argumento a curva definida
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # gerar as chaves privada e pública
    private_key_dsa = ec.generate_private_key(default_curve, default_backend())
    pub_dsa = private_key_dsa.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # envia a chave pública
    conn.send(pub_dsa)

    # cálculo da assinatura
    signature = private_key_dsa.sign(pub, ec.ECDSA(hashes.SHA256()))  # ECDSA recebe como argumento a hash256

    peer_pub_dsa = serialization.load_pem_public_key(
        conn.recv(),
        backend=default_backend())

    conn.send(pub)
    conn.send(signature)

    # ASSINAR

    try:
        peer_pub = conn.recv()
        sig = conn.recv()
        peer_pub_dsa.verify(sig, peer_pub, ec.ECDSA(hashes.SHA256()))
        print("ok ecdh")
    except InvalidSignature:
        print("fail ecdh")

    # shared_key calculation
    peer_pub_key = serialization.load_pem_public_key(
        peer_pub,
        backend=default_backend())
    shared_key = pk.exchange(ec.ECDH(), peer_pub_key)  # em vez de se trocar apenas a chave, tambem se troca ECDH

    # confirmation
    my_tag = hashs(bytes(shared_key))
    conn.send(my_tag)
    peer_tag = conn.recv()
    if my_tag == peer_tag:
        print('OK ECDSA')
        return my_tag
    else:
        print('FAIL ECDSA')


message_size = 2**10


def Emitter(conn):
    # Acordo de chaves DH e assinatura DSA
    key = ECDH(conn)
    
    # Mensagem
    inputs = io.BytesIO(bytes('1'*message_size, 'utf-8'))
   
    # CHACHA2020POLY1305
    # key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    # aad = b"HELLOWORLD"
    # nonce = os.urandom(12)
    nonce = get_nonce(12)
    
    # iv para a cifra
    # iv  = os.urandom(16)
    
    # Cifra
    # cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
    #                   backend=default_backend()).encryptor()
    
    # HMAC
    # mac = my_mac(key)
    
    # conn.send(iv) # Envio do iv
    conn.send(nonce)
    buffer = bytearray(32)  # Buffer onde vão ser lidos os blocos
    
    # lê, cifra e envia sucessivos blocos do input 
    try:     
        while inputs.readinto(buffer):
            cipher = chacha.encrypt(nonce, bytes(buffer), None)
            # ciphertext = cipher.update(bytes(buffer))
            # mac.update(ciphertext)
            # conn.send((ciphertext, mac.copy().finalize()))
            conn.send(cipher) 

        # conn.send((cipher.finalize(), mac.finalize()))    # envia a finalização
        conn.send(cipher)
    except Exception as err:
        print("Erro no emissor: {0}".format(err))

    inputs.close()          # fecha a 'input stream'
    conn.close()            # fecha a conecção


def Receiver(conn):
    # Acordo de chaves DH e assinatura DSA
    key = ECDH(conn)
    
    # Inicializa um output stream para receber o texto decifrado
    outputs = io.BytesIO()
    
    # Recebe o iv
    # iv = conn.recv()
    nonce = conn.recv()
    # Cifra
    # cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
    #                   backend=default_backend()).decryptor()
    chacha = ChaCha20Poly1305(key)

    # HMAC
    # mac = my_mac(key)
    
    # operar a cifra: ler da conecção um bloco, autenticá-lo, decifrá-lo e escrever o resultado no 'stream' de output
    try:
        while True:
            try:
                buffer = conn.recv()
                ciphertext = bytes(buffer)
                # mac.update(ciphertext)
                ct = chacha.decrypt(nonce, ciphertext, None)
                # if tag != mac.copy().finalize():
                #     raise InvalidSignature("erro no bloco intermédio")
                outputs.write(ct)
                if not buffer:
                    # if tag != mac.finalize():
                    #     raise InvalidSignature("erro na finalização")
                    outputs.write(ct)
                    break
                    
            # except InvalidSignature as err:
            #     raise Exception("autenticação do ciphertext ou metadados: {}".format(err))
            #     cipher = conn.recv()
            #     pt = chacha.decrypt(nonce, cipher, None)
                # print('pt --> ', pt)
            except InvalidSignature as err:
                raise Exception("autenticação do ciphertext ou metadados: {}".format(err))
        print(outputs.getvalue())     # verificar o resultado
                
    except Exception as err:
        print("Erro no receptor: {0}".format(err))
        
    outputs.close()    # fechar 'stream' de output
    conn.close()       # fechar a conexão


BiConn(Emitter, Receiver, timeout=30).auto()




