# coding=utf-8
import os
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

import logging
from log import *
import json
import socket
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
import utilsAES
import base64
import time
from socket import *
from select import *


TERMINATOR = "\r\n"
BUF_SIZE = 512 * 1024
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2

class Client:
    count = 0

    def __init__(self, socket, addr, name, cipher):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None  #id gerado durante o handshake entre o cliente e o servidor
        self.sa_data = None
        self.cipher = cipher    #cipherspec do servidor
        self.cipherspec = ['ECDHE-AES128-SHA', 'ECDHE-AES256-SHA'] #cipherspecs do cliente
        self.status = 'DISCONNECTED'
        self.shared_key = None #Chave secreta partilhada entre o cliente e o servidor(DH-elliptic curve)
        self.name = name
        self.clients_on = {} #dicionário com a informaçao de outros clientes ligados a este cliente
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.bind = self.sock.bind(("127.0.0.1", 0)) #ip do servidor
        self.connect = self.sock.connect(("127.0.0.1", 8080)) #porto 8080
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend()) #chave privada do cliente para geraçao da chave secreta entre o cliente e o servidor
        self.public_key = self.private_key.public_key() #chave publica do cliente que vai ser dada ao servidor para ele poder gerar a chave secreta
        self.delete_clients = {} #dicionario de clientes a eliminar apos a fase "Client-Disconnect"
        self.counter = 0    #contador para estabelecer a nova chave secreta entre os clientes quando recebe x mensagens

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r; addr:%s; name:%r; status:%s)" % (self.id, str(self.addr), self.name, self.status)

    def asDict(self):
        return {'id': self.id}

    def generate_nonce(self, length=8):
        """Generate pseudorandom number"""
        return ''.join([str(random.randint(0, 9)) for i in range(length)])

    def stop(self):
        """Stop the server by closing all the sockets"""
        logging.info("Stopping server!!!\n")
        try:
            self.sock.close()
        except:
            logging.exception("Server.stop\n")
        self.clients_on.clear()

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]

    def OptionsMenu(self, input):
        '''
                Função para filtar o input do utilizador e garantir que este está adequado às opções existentes.
                Por outras palavras, controlo de input.
                :param input:
                :return:
        '''
        array_1 = input.strip("\n").split("#")
        array_2 = input.strip("\n").split("##")

        if input.strip("\n") == "list":
            self.GetList()
        elif array_1[0] == "connect" and len(array_1) == 3:
            self.ClientHandshake(input.strip("\n").split("#")[1], input.strip("\n").split("#")[2])
        elif input.strip("\n") == "disconnect":
            self.ServerDisconnect()
        elif array_1[0] == "disconnect" and len(array_1) == 2:
            self.VerifyIfConnected(input.strip("\n").split("#")[1], 0)
        elif array_2[0] == "send" and len(array_2) == 3:
            self.SendMsg(input.strip("\n").split("##")[1], input.strip("\n").split("##")[2])
        elif input.strip("\n") == "connected":
            self.ShowConnectedPeers()
        elif input.strip("\n") == "menu":
            self.DisplayOptions()
        elif input.strip("\n") == "ciphers":
            print "[1]'ECDHE-AES128-SHA'\n[2]'ECDHE-AES256-SHA'\n[3] Enviar ambos e o servidor escolher\n\n"
        else:
            logging.error("Opção Inválida!")
            self.DisplayOptions()

    def DisplayOptions(self):
        '''
               Menu com as opções de utilização por parte do utilizador
               :return:
        '''
        print "\n\n\n"
        print 'Secure IM Client'
        print 'Lista de Comandos'
        print '-> list - Lista os ID de todos os clientes ligados ao server'
        print '-> connect#Numero#cipher - conectar ao ID com aquele número'
        print '-> send##ID##mensagem - enviar uma mensagem ao cliente com o ID especificado'
        print '-> disconnect - desconectar do servidor'
        print '-> disconnect#ID - desconectar a sessão end 2 end com o cliente com o ID especificado'
        print '-> connected - mostra todos os clientes conectados'
        print '-> ciphers - mostra os cipherspecs disponiveis'
        print '-> menu - voltar a mostrar o menu'
        print "\n\n\n"

    def GetList(self):
        '''
            Funçao que envia uma mensagem do tipo "list" para o utilizador, de forma a receber informação sobre todos os clientes connectados ao servidor.
        :return:
        '''
        msg = {"type": "list"} #mensagem que queremos pedir
        new_msg = json.dumps(msg)

        #cifrar a mensagem
        (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.shared_key, new_msg, self.cipher)

        sec = {"type": "secure", "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash}, "payload": {"msg": msg_c}}
        data = json.dumps(sec)
        self.sock.send(data + TERMINATOR)

    def GenerateCipherParameters(self, secret_key, input_msg, cipher):
        '''
                    Função para gerar os parametros que servem para garantir a integridade.
                    Geração de o IV usado(tem de ser diferente a cada msg)
                    Geração de um HASH/HMAC da mensagem antes de ser cifrada
                    Geração da mensagem cifrada
                    Geração do salt a ser usado para criar a chave derivada para cifrar a mensagem
                    Geração do salt a ser usado para criar o HASH/HMAC

        :param secret: segredo acordado entre os dois endereços
        :param msg_before: mensagem para ser cifrada
        :param cipher:  cifra a ser usada
        :return:
        '''
        my_salt_cipher = os.urandom(16)
        my_salt_hmac = os.urandom(16)
        iv = utilsAES.generateIV()
        dev_cipher_key = utilsAES.derivate(secret_key, my_salt_cipher, cipher)
        dev_hmac_key = utilsAES.derivate(secret_key, my_salt_hmac, cipher)
        req_cipher = utilsAES.encryptAES(dev_cipher_key, input_msg, iv)
        hash_msg_cipher = utilsAES.generateHashMsg(dev_hmac_key, req_cipher)

        return base64.b64encode(iv), base64.b64encode(req_cipher + hash_msg_cipher), base64.b64encode(my_salt_cipher), base64.b64encode(my_salt_hmac)

    def ClientHandshake(self, id, cipher):
        '''
            Funçao que certifica o handshake entre dois clientes através de um envio de uma mensagem para o servidor.
            Enviamos juntamente com esta a mensagem a cifra que pretendemos utilizar para que o servidor verifique se os dois clientes suportam a mesma cifra.

        :param id:
        :param cipher:
        :return:
        '''
        if cipher == '1':
            cip = ['ECDHE-AES128-SHA']
        elif cipher == '2':
            cip = ['ECDHE-AES256-SHA']
        elif cipher == '3':
            cip = self.cipherspec
        else:
            logging.warning("Invalid Option for the Client-Client Handshake cipher. Please try another one...\n")
            self.DisplayOptions()
            return

        #a mensagem que pretendemos pedir
        msg = {"type": "client-connect", "src": self.id, "dst": id, "phase": 1, "ciphers": cip, "data": {}}
        new_msg = json.dumps(msg)

        #cifragem da mensagem
        (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.shared_key, new_msg, self.cipher)

        sec = {"type": "secure", "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash}, "payload": {"msg": msg_c}}
        data = json.dumps(sec)
        self.sock.send(data + TERMINATOR)

    def ClientDisconnect(self, client_id, flag):
        '''
            Funçao que gera a primeira mensagem na fase client-client disconnect.
            Enviamos uma mensagem cifrada para o outro cliente para pedir para ele disconnectar.
            O principio da resposta do outro cliente é o mesmo dos outros processos.
            Criamos um hmac com a mensagem que decifra e verificar se este bate certo com o hmac enviado pelo cliente.
            No entanto, esta funçao apenas trata do envio da primeira mensagem do cliente que começa o processo de disconnect.

        :param client_id: id do cliente que oretendemos disconnectar.
        :param flag: saber se o disconnect do cliente é do tipo "client-disconnect" ou se é um disconnect forçado pelo outro cliente se estiver a desligar do servidor.
        :return:
        '''

        #buscar a chave secreta partilhada entre o cliente e o servidor
        salt = os.urandom(16)
        secret_key = self.clients_on[client_id]['secret']

        msg_1 = "Disconnect"
        #cifragem da primeira mensagem
        (IV_sending1, cipher_msg, salt_cipher, salt_hash) = self.GenerateCipherParameters(secret_key, msg_1, self.clients_on[client_id]['cipher'])

        msg = {"type": "client-disconnect", "src": self.id, "dst": client_id,
               "data":{'flag': flag, 'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hash, 'IV': IV_sending1, 'phase': 1}}
        new_msg = json.dumps(msg)

        #cifragem da mensagem
        (IV_sending2, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.shared_key, new_msg, self.cipher)

        sec = {"type": "secure", "sa-data": {"IV": IV_sending2, "salt-cipher": salt_cipher, "salt-hash": salt_hash}, "payload": {"msg": msg_c}}
        data = json.dumps(sec)
        self.sock.send(data + "\n\n")

    def ServerDisconnect(self):
        '''
             Funçao que trata da primeira mensagem a ser enviada quando o cliente se quer disconectar do servidor
             Vai por o valor 1 na função: self.ClientDisconnect(id_client, flag) para que os clientes ligados a estes saibam que este cliente vai acabar a ligação com o servidor e assim o possam retirar dos clientes ligados a si.
        :return:
        '''
        for key, value in self.clients_on.iteritems():
            logging.warning('Server disconnected from the client' + value['name'])
            self.ClientDisconnect(key, 1)

        #a mensagem que pretendemos pedir
        msg = {"type": "disconnect", "src": self.id, "data": {}}
        new_msg = json.dumps(msg)

        # cifragem da mensagem
        (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.shared_key, new_msg, self.cipher)

        sec = {"type": "secure", "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
               "payload": {"msg": msg_c}}
        data = json.dumps(sec)
        self.sock.send(data + "\n\n")

    def VerifyIfConnected(self, client_id, flag):
        '''
            Verificar se o cliente que pretendemos disconnectar se encontra connectado a este cliente.
            Para impedir que seja enviado um pedido de disconnect a um cliente que nem sequer esta connectado.

        :param client_id: id do cliente que vamos verificar se encontra dentro do dicionario com a informaçao dos clientes connectados(self.clients_on)
        :param flag: flag para saber se o disconnect do cliente vem de desconnectar apenas um cliente ou se é um disconnect forçado pelo facto de estarmos a fazer disconnect com o servidor.
                     Ou seja, ao enviarmos um disconnect apenas para o servidor, temos de enviar para os outros clientes que estao connectados connosco para que eles nos retirem da sua lista de clientes connectados(self.clients_on)

        :return:
        '''

        clients_connect = []
        for key in self.clients_on:
            clients_connect.append(key)

        if client_id in clients_connect:
            self.ClientDisconnect(client_id, flag)
        else:
            logging.warning("\n\nO cliente " + str(client_id) + "nao se encontra conectado!\n")
            self.DisplayOptions()

    def SendMsg(self, client_id, input_msg):
        '''
            Esta funçao têm a funçao de enviar as mensagens do tipo "client-com"
            Ciframos a mensagem e enviamos um HMAC criado a partir da mensagem original para o cliente que recebe a mensagem ter a certeza que esta mensagem nao foi alterada.
        :param client_id: id do cliente de destino da mensagem
        :param input_msg: mensagem a ser enviada
        :return:
        '''
        #verificar se o id é valido
        if client_id in self.clients_on.keys():
            #buscar a secret_key partilhada
            secret_key = self.clients_on[client_id]['secret']
            #cifragem da mensagem
            (IV_sending1, msg_cipher, salt_cipher, salt_hash) = self.GenerateCipherParameters(secret_key, input_msg, self.clients_on[client_id]['cipher'])

            #mensagem que pretendemos pedir
            msg = {"type": "client-com", "src": self.id, "dst": client_id, "data": {'msg-cipher': msg_cipher, 'salt-cipher': salt_cipher, 'salt-hash': salt_hash, 'IV': IV_sending1}}
            new_msg = json.dumps(msg)

            #cifragem da mensagem
            (IV_sending2, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.shared_key, new_msg, self.cipher)

            sec = {"type": "secure", "sa-data": {"IV": IV_sending2, "salt-cipher": salt_cipher, 'salt-hash': salt_hash}, "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.sock.send(data + "\n\n")
        else:
            logging.warning("O client_id que foi fornecido nao é valido! Tente novamente...\n")
            self.DisplayOptions()

    def ShowConnectedPeers(self):
        '''
            Esta funçao serve para mostrar os clientes que encontram connectados com o cliente em questao.
            Desta forma o utilizador pode ver para que clientes pode enviar mensagens e as quais falta conectar-se.
        :return:
        '''
        #lista de peers que estao na lista self.clients_on
        print "Lista de peers do cliente: \n"
        for key, value in self.clients_on.iteritems():
            print "-> ID do Client: " + key
            print "-> Nome do Client: " + value['name'] + "\n"
        self.DisplayOptions()

    def flushin(self):
        '''
            Read a chunk  of data from this client.
            Enqueue any complete requests.
            Leave incomplete requests in the buffer.
            This is called whenever data is available from client socket.
        :return:
        '''
        data = None
        try:
            data = self.sock.recv(BUF_SIZE)
            #logging.info("Received data. Message: \n%r", data)
        except:
            logging.error("ERROR! Invalid data received! Closing...\n")
            self.stop()
        else:
            if len(data) > 0:
                reqs = self.parseReqs(data)
                for req in reqs:
                    self.handleRequest(req)
            else:
                self.stop()

    def flushout(self):
        """Write a chunk of data to the client.
           This is called whenever the client socket is ready to transmit data."""

        try:
            data_sent = self.sock.send(self.bufout[:BUF_SIZE])
            #logging.info("Sent %d bytes. Message:\n%r", sent, self.bufout[:sent])
            self.bufout = self.bufout[data_sent:] #leave remaining to be sent later
            '''
                        É no flushout que apagamos toda a informação sobre os utilizadores que estavam conectados a este.
                        Isto porque ao apagarmos os dados do cliente logo quando estavamos a trocar fases, ia fazer com que ao enviar a ultima
                        mensagem os dados do cliente ja nao estivessem disponiveis.
                        Dessa forma, decidimos guardar num dicionario (self.to_delete)extra o id dos clientes que vao ser desconectados. E aqui apagamos a informação
                        referente aos mesmos(self.clients_on)
            '''
            if len(self.delete_clients) > 0:
                for key in self.delete_clients.keys():
                    del self.clients_on[key]
                self.delete_clients = {}
        except:
            #logging.error("Cannot write to client %s. Closing", client)
            self.stop()

    def handleRequest(self, request):
        """Handle a request from a client socket."""
        try:
            #logging.info("HANDLING Message: %r", repr(request))
            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return
            if 'type' not in req:
                return
            if req['type'] == 'ack':
                return #ignore for now
            self.sendResult({'type': 'ack'})
            if req['type'] == 'connect':
                self.processConnect(req)
            elif req['type'] == 'secure':
                self.processSecure(req)
        except Exception, e:
            logging.exception("Could not handle the request!\n")

    def DecipherMessage(self, iv, input_msg, salt_cipher, salt_hmac, secret_key, cipher):
        '''
            Funçao para decifrar a mensagem e verificar um HASH/HMAC a partir de uma mensagem cifrada
        :param iv: IV utilizado para fazer a encriptaçao da mensagem, e por isso é necessario para a decriptaçao
        :param input_msg: Mensagem cifrada enviada e que tem de ser decifrada
        :param salt_cipher: Salt usado para criar a chave derivada usada para cifrar
        :param salt_hmac: Salt usado para gerar o HASH/HMAC da mensagem original
        :param secret_key: Chave secreta gerada entre o source e o destino
        :param cipher: Cifra usada e acorda entre o source e o destino
        :return:
        '''
        dev_cipher_key = utilsAES.derivate(secret_key, salt_cipher, cipher)
        dev_hmac_key = utilsAES.derivate(secret_key, salt_hmac, cipher)
        try:
            hash_msg = utilsAES.verifyHashMsg(dev_hmac_key, input_msg[:-32], input_msg[-32:])
        except:
            logging.error('A mensagem foi alterada...\n')
            return 'ERROR', ''
        deciphered_msg = utilsAES.decryptAES(dev_cipher_key, input_msg[:-32], iv)
        return 'OK', deciphered_msg

    def processConnect(self, request):
        '''
            A funçao processConnect serve para controlar o envio e recepçao de mensagens na fase de handshake entre o cliente e o servidor.
            A primeira parte deste handshake trata de acordar o cipherspec que vai ser utilizado pelo utilizador.
            O utilizador envia o que pretende e se este corresponde a algum cipherspec do servidor e é esse que será usado.
            Caso o utilizador nao queira, é o servidor que escolhe o cipherspec que tiver mair valor criptográfico.
            (PS: Esta escolha é feita logo na main através de input)

            A segunda parte consiste na criaçao de uma secret_key com o servidor através de uma DH elliptic curve.

            A terceira parte consiste em cifrar uma mensagem que envia o HMAC(feito com a mensagem antes de ser cifrada).
            Se o servidor conseguir gerar um HMAC igual ao que cliente envia(através da mensagem decifrada) isso quer dizer que a sucedida e por isso o handshake pode ser finalizado.
            O servidor faz o mesmo para o cliente, e este tem de conseguir chegar ao mesmo valor de HMAC.
            Após isto o handshake cliente-servidor é concluido.
        :param req: request que tras a informaçao da mensagem recebida.
        :return:
        '''
        phase = request['phase']

        if phase == 1:
            self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.public_key = self.private_key.public_key()

            sk = utilsAES.loadPublicKey(str(request['data']['pub']))
            self.shared_key = self.private_key.exchange(ec.ECDH(), sk)

            #mensagem que pretendemos pedir
            msg = {'name': self.name, 'type': 'connect', 'phase': phase+1, 'ciphers': self.cipher, 'id': self.generate_nonce(), 'data':{'pub': utilsAES.serializePublicKey(self.public_key)}}
            data = json.dumps(msg)
            self.sock.send(data + "\n\n")
            return

        if phase == 2:
            cipher = request['ciphers']
            if len(cipher) == 0:
                logging.error("Cipherspecs do not match. It's impossible to make a connection...\n")
                os._exit(1)
            if len(request['ciphers']) == 2 and len(self.cipher) == 2:
                self.cipher = self.cipherspec[1]
            elif self.cipher[0] in request['ciphers']:
                self.cipher = self.cipher[0]
            else:
                logging.error("Cipherspecs do not match. It's impossible to make a connection...\n")
                os._exit(1)

            #mensagem que pretendemos pedir
            msg = {'name': self.name, 'type': 'connect', 'phase': phase+1, 'ciphers': self.cipher, 'id': self.generate_nonce(), 'data':{'pub': utilsAES.serializePublicKey(self.public_key)}}
            data = json.dumps(msg)
            self.sock.send(data + TERMINATOR)

        if phase == 3:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['cipher-msg']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)
            if dec_hash_msg == 'OK':
                msg_1 = "hello"
                #cifragem da mensagem
                (IV_sending, cipher_msg, salt_cipher, salt_hmac) = self.GenerateCipherParameters(self.shared_key, msg_1, self.cipher)
                #mensagem que pretendemos pedir
                msg = {'name': self.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.cipher, 'id': self.generate_nonce(),
                       'data':{'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hmac, 'IV': IV_sending, 'id': self.id}}
                data = json.dumps(msg)
                self.sock.send(data + "\n\n")
                return
            else:
                logging.warning("Connexao com o servidor invalida! Vamos começar tudo de novo...\n")
                #mensagem que pretendemos pedir
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'cipher': self.cipher, 'id': self.id, 'data':{}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

        if phase == 4:
            sk = utilsAES.loadPublicKey(str(request['data']['pub']))
            self.shared_key = self.private_key.exchange(ec.ECDH(), sk)
            msg_1 = "hello"
            #cifragem da mensagem
            (IV_sending, cipher_msg, salt_cipher, salt_hmac) = self.GenerateCipherParameters(self.shared_key, msg_1, self.cipher)
            #mensagem que pretendemos pedir
            msg = {'name': self.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.cipher, 'id': self.generate_nonce(),
                   'data': {'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hmac, 'IV': IV_sending}}
            data = json.dumps(msg)
            self.sock.send(data + "\n\n")
            return

        if phase == 5:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['cipher-msg']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)
            if dec_hash_msg == 'OK':
                if decrypted_payload_msg == 'ERROR':
                    logging.info("Erro na geraçao da chave secreta. É impossivel conectar com o servidor!\n")
                    os._exit(1)
                    return
                else:
                    self.status = "CONNECTED"
                    self.DisplayOptions()
                    logging.info("\n\nO tempo default ou numero de mensagens foi excedido. \nPor precaução vamos estabelecer novas chaves secretas.\n")
                    logging.info("\nNova conexao foi estabelicida entre o cliente e o servidor!\n")
                    return
            else:
                logging.info("Um erro ocorreu na geração da chave secreta. É impossivel estabelecer conexao com o servidor. Vamos tentar estabelecer uma nova ligaçao\n")
                #mensagem que pretendemos pedir
                msg = {'name': self.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.cipher, 'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

        if phase == 6:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['cipher-msg']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)
            if dec_hash_msg == 'OK':
                msg_1 = "hello"
                #cifragem de mensagem
                (IV_sending, cipher_msg, salt_cipher, salt_hmac) = self.GenerateCipherParameters(self.shared_key, msg_1, self.cipher)
                self.id = self.generate_nonce()
                #mensagem que pretendemos pedir
                msg = {'name': self.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.cipher, 'id': self.generate_nonce(),
                       'data': {'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hmac, 'IV': IV_sending, 'id': self.id}}
                data = json.dumps(msg)
                self.sock.send(data + "\n\n")
                self.status = "CONNECTED"
                self.DisplayOptions()
                logging.info("O cliente foi connectado com o servidor!\n")
                return
            else:
                logging.info("Ocorreu um erro na geraçao da chave secreta. Foi impossivel estabelecer conexao com o servidor. Vamos tentar estabelecer uma nova ligaçao.\n")
                #mensagem que pretendemos pedir
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'cipher': self.cipher, 'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

        if phase == 8:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['id']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)
            if dec_hash_msg == 'OK':
                if 'id' in json.loads(decrypted_payload_msg).keys():
                    self.id = decrypted_payload_msg['id']
            else:
                logging.info("Ocorreu um erro na geraçao da chave secreta. Foi impossivel estabelecer conexao com o servidor. Vamos tentar estabelecer uma nova ligaçao.\n")
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'cipher': self.cipher, 'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

    def processSecure(self, request):
        if 'payload' not in request:
            logging.warning("The secure message has missing fields\n")
            return

        #This is a secure message
        #The inner message is encrypted for us. The message must be decrypted and validated.
        (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['sa-data']['IV']),
                                                                     base64.b64decode(request['payload']['msg']),
                                                                     base64.b64decode(request['sa-data']['salt-cipher']),
                                                                     base64.b64decode(request['sa-data']['salt-hash']),
                                                                     self.shared_key,
                                                                     self.cipher)

        if dec_hash_msg != 'OK':
            logging.warning('A mensagem foi adulterada!\n')
            self.stop()
            return
        decrypted_payload_msg = json.loads(decrypted_payload_msg)
        if not 'type' in decrypted_payload_msg.keys():
            logging.warning("The secure message does not have a inner frame type!\n")
            return

        if decrypted_payload_msg['data'] == 'doesntexist':
            self.ClientGotRekt(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'list':
            self.processClientConnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'client-connect':
            self.processClientConnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'ack':
            self.recvAck(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'disconnect':
            self.processServerDisconnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'client-disconnect':
            self.processClientDisconnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'client-com':
            self.sendAck(decrypted_payload_msg)
            self.processRecvMsg(decrypted_payload_msg)
            return


    def loop(self):
        '''
            Esta função é baseada no código do servidor, no entanto, a nossa wlist vai ser o nosso socket, visto que
            tudo aquilo que o cliente envia tem de passar pelo servidor.
            Além dsso, o nosso rlist também tem o:  "sys.stdin" para poder receber input do utilizador pela consola e
            agir de acordo com o que o utilizador pretende
        '''
        while True:
            #logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            if len(self.bufout) > 0:
                wlst = [self.sock]
            else:
                wlst = []

            (rl, wl, xl) = select([self.sock, sys.stdin], wlst, [self.sock])
            #logging.debug("select: %s %s %s", rl, wl, xl)

            #Deal with incoming data
            #if len(rl) > 0
            for s in rl:
                if s == self.sock:
                    self.flushin()
                elif s == sys.stdin:
                    self.OptionsMenu(sys.stdin.readline())

            #Deal with outgoing data
            #if len(wl) > 0:
            for s in wl:
                self.flushout()

            #if len(xl) > 0:
            for s in xl:
                logging.error("EXCEPTION IN %s! Closing...\n", s)
                self.stop()

    def sendResult(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        log(logging.INFO, "Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)" % self)

