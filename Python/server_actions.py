import logging
from log import *
from server_registry import *
from server_client import *
import json
import socket
from socket import *

class ServerActions:
    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'connect': self.processConnect,
            'disconnect': self.processServerDisconnect,
            'secure': self.processSecure,
            'client-connect': self.processClientConnect,
            'client-disconnect': self.processClientDisconnect,
            'ack': self.recvAck,
            'client-com': self.sendAck,
            'doesntexist': self.ClientGotRekt
        }

        self.registry = ServerRegistry()
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.client = None
        while True:
            try:
                logging.info("Starting Secure IM Server\n")
                name = raw_input("Indique o nome do cliente:\n\n--->")

                num = 0
                out = False
                while out == False:
                    num = raw_input("\n\nIndique a cipherspec que pretende utilizar:\n"
                                    "[1]'ECDHE-AES128-SHA'\n"
                                    "[2]'ECDHE-AES256-SHA'\n"
                                    "[3] Enviar ambos e o servidor escolher\n\n--->")
                    if num in ['1', '2', '3']:
                        out = True
                if num == '1':
                    cipher = ['ECDHE-AES128-SHA']
                elif num == '2':
                    cipher = ['ECDHE-AES256-SHA']
                else:
                    cipher = ['ECDHE-AES128-SHA', 'ECDHE-AES256-SHA']

                self.client = Client(socket=socket(AF_INET, SOCK_STREAM), addr="127.0.0.1", name=name, cipher=cipher)
                #mensagem que pretendemos pedir
                msg = {'name': self.client.name, 'type': 'connect', 'phase': 1, 'cipher': self.client.cipherspec, 'id': self.client.id, 'data': {}}
                data = json.dumps(msg)
                self.client.sock.send(data + TERMINATOR)
                self.client.loop()
            except KeyboardInterrupt:
                self.client.stop()
                try:
                    logging.info("Press CTRL-C again within 2 secs to quit...\n")
                    time.sleep(2)
                except KeyboardInterrupt:
                    logging.info("CTRL-C pressed twice: Quitting!\n")
                    break
            except:
                logging.exception("An error occured in the server. Quiting!\n")
                sys.exit(0)


    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                log(logging.ERROR, "Message has no TYPE field")
                return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"})

        except Exception, e:
            logging.exception("Could not handle request")

    def processCreate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        uuid = data['uuid']
        if not isinstance(uuid, int):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        if self.registry.userExists(uuid):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"})
            return

        me = self.registry.addUser(data)
        client.sendResult({"result": me.id})

    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult({"result": userList})

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult(
            {"result": self.registry.userNewMessages(user)})

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult({"result": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]})

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'msg'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        srcId = int(data['src'])
        dstId = int(data['dst'])
        msg = str(data['msg'])
        copy = str(data['copy'])

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Save message and copy

        response = self.registry.sendMessage(srcId, dstId, msg, copy)

        client.sendResult({"result": response})

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        fromId = int(data['id'])
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Read message

        response = self.registry.recvMessage(fromId, msg)

        client.sendResult({"result": response})

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"})

        fromId = int(data["id"])
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
        
        fromId = int(data['id'])
        msg = str(data["msg"])

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error", "wrong parameters"})
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult({"result": response})

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

    def DisplayOptions(self):
        '''
               Menu com as opções de utilização por parte do utilizador
               :return:
        '''
        print "\n\n\n"
        print 'Secure IM Client'
        print 'Lista de Comandos'
        print '-> list - Lista os ID de todos os clientes ligados ao server'
        print '-> connect#Numero#cipher - conectar ao ID com aquele numero'
        print '-> send##ID##mensagem - enviar uma mensagem ao cliente com o ID especificado'
        print '-> disconnect - desconectar do servidor'
        print '-> disconnect#ID - desconectar a sessao end 2 end com o cliente com o ID especificado'
        print '-> connected - mostra todos os clientes conectados'
        print '-> ciphers - mostra os cipherspecs disponiveis'
        print '-> menu - voltar a mostrar o menu'
        print "\n\n\n"

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
            self.client.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.client.public_key = self.client.private_key.public_key()

            sk = utilsAES.loadPublicKey(str(request['data']['pub']))
            self.client.shared_key = self.client.private_key.exchange(ec.ECDH(), sk)

            #mensagem que pretendemos pedir
            msg = {'name': self.client.name, 'type': 'connect', 'phase': phase+1, 'ciphers': self.client.cipher, 'id': self.client.generate_nonce(), 'data':{'pub': utilsAES.serializePublicKey(self.client.public_key)}}
            data = json.dumps(msg)
            self.client.sock.send(data + "\n\n")
            return

        if phase == 2:
            cipher = request['ciphers']
            if len(cipher) == 0:
                logging.error("Cipherspecs do not match. It's impossible to make a connection...\n")
                os._exit(1)
            if len(request['ciphers']) == 2 and len(self.client.cipher) == 2:
                self.client.cipher = self.client.cipherspec[1]
            elif self.client.cipher[0] in request['ciphers']:
                self.client.cipher = self.client.cipher[0]
            else:
                logging.error("Cipherspecs do not match. It's impossible to make a connection...\n")
                os._exit(1)

            #mensagem que pretendemos pedir
            msg = {'name': self.client.name, 'type': 'connect', 'phase': phase+1, 'ciphers': self.client.cipher, 'id': self.client.generate_nonce(), 'data':{'pub': utilsAES.serializePublicKey(self.client.public_key)}}
            data = json.dumps(msg)
            self.client.sock.send(data + TERMINATOR)

        if phase == 3:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['cipher-msg']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.client.shared_key,
                                                                       self.client.cipher)
            if dec_hash_msg == 'OK':
                msg_1 = "hello"
                #cifragem da mensagem
                (IV_sending, cipher_msg, salt_cipher, salt_hmac) = self.GenerateCipherParameters(self.client.shared_key, msg_1, self.client.cipher)
                #mensagem que pretendemos pedir
                msg = {'name': self.client.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.client.cipher, 'id': self.client.generate_nonce(),
                       'data':{'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hmac, 'IV': IV_sending, 'id': self.client.id}}
                data = json.dumps(msg)
                self.client.sock.send(data + "\n\n")
                return
            else:
                logging.warning("Connexao com o servidor invalida! Vamos comecar tudo de novo...\n")
                #mensagem que pretendemos pedir
                msg = {'name': self.client.name, 'type': 'connect', 'phase': 1, 'cipher': self.client.cipher, 'id': self.client.id, 'data':{}}
                data = json.dumps(msg)
                self.client.sock.send(data + TERMINATOR)
                return

        if phase == 4:
            sk = utilsAES.loadPublicKey(str(request['data']['pub']))
            self.client.shared_key = self.client.private_key.exchange(ec.ECDH(), sk)
            msg_1 = "hello"
            #cifragem da mensagem
            (IV_sending, cipher_msg, salt_cipher, salt_hmac) = self.GenerateCipherParameters(self.client.shared_key, msg_1, self.client.cipher)
            #mensagem que pretendemos pedir
            msg = {'name': self.client.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.client.cipher, 'id': self.client.generate_nonce(),
                   'data': {'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hmac, 'IV': IV_sending}}
            data = json.dumps(msg)
            self.client.sock.send(data + "\n\n")
            return

        if phase == 5:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['cipher-msg']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.client.shared_key,
                                                                       self.client.cipher)
            if dec_hash_msg == 'OK':
                if decrypted_payload_msg == 'ERROR':
                    logging.info("Erro na geracao da chave secreta. E impossivel conectar com o servidor!\n")
                    os._exit(1)
                    return
                else:
                    self.client.status = "CONNECTED"
                    self.DisplayOptions()
                    logging.info("\n\nO tempo default ou numero de mensagens foi excedido. \nPor precaucao vamos estabelecer novas chaves secretas.\n")
                    logging.info("\nNova conexao foi estabelicida entre o cliente e o servidor!\n")
                    return
            else:
                logging.info("Um erro ocorreu na geracao da chave secreta. E impossivel estabelecer conexao com o servidor. Vamos tentar estabelecer uma nova ligacao\n")
                #mensagem que pretendemos pedir
                msg = {'name': self.client.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.client.cipher, 'id': self.client.id, 'data': {}}
                data = json.dumps(msg)
                self.client.sock.send(data + TERMINATOR)
                return

        if phase == 6:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['cipher-msg']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.client.shared_key,
                                                                       self.client.cipher)
            if dec_hash_msg == 'OK':
                msg_1 = "hello"
                #cifragem de mensagem
                (IV_sending, cipher_msg, salt_cipher, salt_hmac) = self.GenerateCipherParameters(self.client.shared_key, msg_1, self.client.cipher)
                self.client.id = self.client.generate_nonce()
                #mensagem que pretendemos pedir
                msg = {'name': self.client.name, 'type': 'connect', 'phase': phase+1, 'cipher': self.client.cipher, 'id': self.client.generate_nonce(),
                       'data': {'cipher-msg': cipher_msg, 'salt-cipher': salt_cipher, 'salt-hash': salt_hmac, 'IV': IV_sending, 'id': self.client.id}}
                data = json.dumps(msg)
                self.client.sock.send(data + "\n\n")
                self.client.status = "CONNECTED"
                self.DisplayOptions()
                logging.info("O cliente foi connectado com o servidor!\n")
                return
            else:
                logging.info("Ocorreu um erro na geracao da chave secreta. Foi impossivel estabelecer conexao com o servidor. Vamos tentar estabelecer uma nova ligacao.\n")
                #mensagem que pretendemos pedir
                msg = {'name': self.client.name, 'type': 'connect', 'phase': 1, 'cipher': self.client.cipher, 'id': self.client.id, 'data': {}}
                data = json.dumps(msg)
                self.client.sock.send(data + TERMINATOR)
                return

        if phase == 8:
            (dec_hash_msg, decrypted_payload_msg) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                       base64.b64decode(request['data']['id']),
                                                                       base64.b64decode(request['data']['salt-cipher']),
                                                                       base64.b64decode(request['data']['salt-hash']),
                                                                       self.client.shared_key,
                                                                       self.client.cipher)
            if dec_hash_msg == 'OK':
                if 'id' in json.loads(decrypted_payload_msg).keys():
                    self.id = decrypted_payload_msg['id']
            else:
                logging.info("Ocorreu um erro na geracao da chave secreta. Foi impossivel estabelecer conexao com o servidor. Vamos tentar estabelecer uma nova ligacao.\n")
                msg = {'name': self.client.name, 'type': 'connect', 'phase': 1, 'cipher': self.client.cipher, 'id': self.client.id, 'data': {}}
                data = json.dumps(msg)
                self.client.sock.send(data + TERMINATOR)
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
                                                                     self.client.shared_key,
                                                                     self.client.cipher)

        if dec_hash_msg != 'OK':
            logging.warning('A mensagem foi adulterada!\n')
            self.client.stop()
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

    def processServerDisconnect(self, server_msg):
        '''
            Apos receber confirmaçao do servidor para haver disconexao, informamos o utilizador que o cliente vai fechar e desligamos a ligacao.
        :param server_msg:
        :return:
        '''
        data = server_msg['data']['valid']
        if data == "OK":
            self.client.status = "DISCONNECT"
            logging.warning("The client has been disconnected from the server...\n")
            os._exit(1)
        else:
            logging.warning('Disconnect error. Still connected!')
        return

    def processClientConnect(self, server_msg):
        '''
               Esta função representa a fase de conexao entre dois clientes.
               A estrutura das fases é muito parecida ao handshake cliente-servidor
               Começamos por enviar uma mensagem ao servidor com o tipo "client-connect".
               Como o servidor tem informação sobre as cifras que cada cliente pode utilizador(informação fornecida no cliente-servidor handshake)
               o servidor vai verificar se as cifras que fornecemos dão match com as cifras do cliente a que nos queremos ligar.
               Ao haver match, podemos criar um conjunto de chaves para gerar um segredo com o outro cliente.
               O resto do processo é identico, cifrar mensagens e gerar HMAC com a mensagem antes de ser cifrada, e o outro cliente
               a gerar um HMAC com a mensagem que decifra e a verificar se os HMAC's correspondem.
               A grande diferença está no facto de tudo o que os clientes comunicam entre si ir cifrado, o que faz com que o servidor
               receba as mensagens de cada um, mas seja incapaz de decifrar. Desta forma garantimos segurança e privacidade na troca de mensagens
               entre os clientes.
       :param msg_ser:
       :return:
       '''
        phase = server_msg['phase']
        if phase == 2:
            valid_ciphers = server_msg['cipher']
            if len(valid_ciphers) == 0:
                if 'exists' in server_msg['data'].keys():
                    if server_msg['data']['exists'] == 'No':
                        logging.warning("Client do not exist. Impossible to connect to the server.")
                else:
                    logging.warning("Cipherspecs do not match. Impossible to connect")
                self.DisplayOptions()
                return
            else:
                #mensagem que pretendemos pedir
                msg = {"type": "client-connect", "src": self.client.id, "dst": server_msg['dst'], "phase": phase+1, "cipher": [valid_ciphers[0]], "data": ""}
            new_msg = json.dumps(msg)
            #cifragem de mensagem
            (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
            sec = {"type": "secure",
                   "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                   "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.client.sock.send(data + "\n\n")
            return

        elif phase == 3:
            #mensagem que pretendemos pedir
            msg = {"type": "client-connect", "src": self.client.id, "dst": server_msg['src'], "phase": phase+1, "cipher": [server_msg['cipher'][0]], "data": {"name": self.client.name}}
            new_msg = json.dumps(msg)
            #cifragem da mensagem
            (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
            sec = {"type": "secure",
                   "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                   "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.client.sock.send(data + TERMINATOR)
            return

        elif phase == 4:
            self.client.clients_on[server_msg['src']] = {}
            client_peer = self.client.clients_on[server_msg['src']]
            client_peer['name'] = server_msg['data']['name']

            #chave secreta(alfa)
            peer_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            #chave publica
            peer_public_key = peer_private_key.public_key()

            client_peer['private_key'] = peer_private_key
            client_peer['public_key'] = peer_public_key
            client_peer['cipher'] = server_msg['cipher'][0]

            #mensagem que pretendemos pedir
            msg = {"type": "client-connect", "src": self.client.id, "dst": server_msg['src'], "phase": phase+1, "cipher": [client_peer['cipher']],
                   "data": {"pub": utilsAES.serializePublicKey(peer_public_key), "name": self.client.name}}
            new_msg = json.dumps(msg)

            #cifragem da mensagem
            (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
            sec = {"type": "secure",
                   "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                   "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.client.sock.send(data + "\n\n")
            return

        elif phase == 5:
            '''
            Gerar secret key
            '''
            src_id = server_msg["src"]
            self.client.clients_on[src_id] = {}
            client_peer = self.client.clients_on[src_id]
            client_peer['name'] = server_msg['data']['name']

            public_key = utilsAES.loadPublicKey(str(server_msg['data']['pub']))
            #secret key(alfa)
            peer_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            #public key
            peer_public_key = peer_private_key.public_key()

            client_peer['private_key'] = peer_private_key
            client_peer['public_key'] = peer_public_key
            client_peer['secret_key'] = peer_private_key.exchange(ec.ECDH(), public_key)
            client_peer['cipher'] = server_msg['cipher'][0]

            '''
            Enviar a minha public_key
            '''
            #mensagem que pretendemos pedir
            msg = {"type": "client-connect", "src": self.client.id, "dst": src_id, "phase": phase+1, "cipher": [client_peer['cipher']],
                   "data": {"pub": utilsAES.serializePublicKey(peer_public_key)}}
            new_msg = json.dumps(msg)
            #cifragem de mensagem
            (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
            sec = {"type": "secure",
                   "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                   "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.client.sock.send(data + "\n\n")
            return

        elif phase == 6:
            dest_id = server_msg['src']
            client_peer = self.client.clients_on[dest_id]
            public_key = utilsAES.loadPublicKey(str(server_msg['data']['pub']))
            client_peer['secret_key'] = client_peer['private_key'].exchange(ec.ECDH(), public_key)

            #enviar mensagem cifrada
            msg_1 = "hello"
            (IV_sending1, cipher_msg, salt_cipher, salt_hash) = self.GenerateCipherParameters(client_peer['secret_key'], msg_1, client_peer['cipher'])
            #mensagem que pretendemos pedir
            msg = {"type": "client-connect", "src": self.client.id, "dst": dest_id, "phase": phase+1, "cipher": [client_peer['cipher']],
                   "data": {"cipher-msg": cipher_msg, "salt-cipher": salt_cipher, "salt-hash": salt_hash, "IV": IV_sending1}}
            new_msg = msg
            #cifragem da mensagem
            (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
            sec = {"type": "secure",
                   "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                   "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.client.sock.send(data + "\n\n")
            return

        elif phase == 7:
            src_id = server_msg['src']
            client_peer = self.client.clients_on[src_id]

            (hash_new_client, dec_msg_client) = self.DecipherMessage(base64.b64decode(server_msg['data']['IV']),
                                                                     base64.b64decode(server_msg['data']['cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-hash']),
                                                                     client_peer['secret_key'],
                                                                     client_peer['cipher'])
            if hash_new_client == 'OK':
                msg_1 = "hello"
                #cifragem da mensagem
                (IV_sending1, cipher_msg, salt_cipher, salt_hash) = self.GenerateCipherParameters(client_peer['secret_key'], msg_1, client_peer['cipher'])
                #mensagem que pretendemos pedir
                msg = {"type": "client-connect", "src": self.client.id, "dst": src_id, "phase": phase+1, "cipher": [client_peer['cipher']],
                       "data": {"cipher-msg": cipher_msg, "salt-cipher": salt_cipher, "salt-hash": salt_hash, "IV": IV_sending1}}
                new_msg = json.dumps(msg)

                #cifragem da mensagem
                (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
                sec = {"type": "secure", "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                       "payload": {"msg": msg_c}}
                data = json.dumps(sec)
                self.client.sock.send(data + "\n\n")
                return
            else:
                logging.warning("Erro. A mensagem foi forjada. A conexao com o cliente foi abortada! Por favor estabeleca de novo a conexao.\n")
                self.client.DisplayOptions()
                return

        elif phase == 8:
            src_id = server_msg['src']
            client_peer = self.client.clients_on[src_id]

            (hash_new_client, dec_msg_client) = self.DecipherMessage(base64.b64decode(server_msg['data']['IV']),
                                                                     base64.b64decode(server_msg['data']['cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-hash']),
                                                                     client_peer['secret_key'],
                                                                     client_peer['cipher'])
            if hash_new_client == 'OK':
                msg_1 = "hello"
                # cifragem da mensagem
                (IV_sending1, cipher_msg, salt_cipher, salt_hash) = self.GenerateCipherParameters(client_peer['secret_key'], msg_1, client_peer['cipher'])
                # mensagem que pretendemos pedir
                msg = {"type": 'client-connect', "src": self.client.id, "dst": src_id, "phase": phase + 1,
                       "cipher": [client_peer['cipher']],
                       "data": {"cipher-msg": cipher_msg, "salt-cipher": salt_cipher, "salt-hash": salt_hash, "IV": IV_sending1}}
                new_msg = json.dumps(msg)

                # cifragem da mensagem
                (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key,
                                                                                            new_msg, self.client.cipher)
                sec = {"type": "secure",
                       "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                       "payload": {"msg": msg_c}}
                data = json.dumps(sec)
                self.client.sock.send(data + "\n\n")
                client_peer['status'] = "CONNECTED"
                client_peer['counter'] = 0
                client_peer['time'] = time.time()
                logging.info("The client " + self.client.id + " has been sucessfully connected to the client " + src_id)
                self.client.DisplayOptions()
                return
            else:
                logging.warning("Erro. A mensagem foi forjada. A conexao com o cliente foi abortada! Por favor estabeleca de novo a conexao.\n")
                self.client.DisplayOptions()
                return
        elif phase == 9:
            src_id = server_msg['src']
            client_peer = self.client.clients_on[src_id]

            (hash_new_client, dec_msg_client) = self.DecipherMessage(base64.b64decode(server_msg['data']['IV']),
                                                                     base64.b64decode(server_msg['data']['cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-hash']),
                                                                     client_peer['secret_key'],
                                                                     client_peer['cipher'])
            if hash_new_client == 'OK':
                client_peer['status'] = "CONNECTED"
                client_peer['counter'] = 0
                client_peer['time'] = time.time()
                logging.info("The client " + self.client.id + "has been sucessfully connected to the client" + src_id)
                self.client.DisplayOptions()
                return
            else:
                logging.warning("Erro. A mensagem foi forjada. A conexao com o cliente foi abortada! Por favor estabeleca de novo a conexao.\n")
                self.client.DisplayOptions()
                return

    def processClientDisconnect(self, server_msg):
        '''
            Esta funcao e usada para desconnectar dois clientes.
            O cliente e aquele que comeca este processo envia uma mensagem cifrada e o cliente que recebe tem de decifrar e gerar o hmac e confirmar o disconnect, enviando uma ultima fase apenas de confirmacao.

        :param server_msg:
        :return:
        '''
        if 'flag' in server_msg['data'].keys():
            flag = server_msg['data']['flag']
            if flag == 1:
                del self.client.clients_on[server_msg['src']]
                return

        phase = server_msg['data']['phase']

        if phase == 1:
            src_id = server_msg['src']
            #def DecipherMessage(self, iv, msg, salt, secret)
            client_peer = self.client.clients_on[src_id]

            (hash_new_client, dec_msg_client) = self.DecipherMessage(base64.b64decode(server_msg['data']['IV']),
                                                                     base64.b64decode(server_msg['data']['cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-cipher']),
                                                                     base64.b64decode(server_msg['data']['salt-hash']),
                                                                     client_peer['secret_key'],
                                                                     client_peer['cipher'])

            if hash_new_client == 'OK':
                msg_1 = "Disconnect"
                #cifragem da mensagem
                (IV_sending1, cipher_msg, salt_cipher, salt_hash) = self.GenerateCipherParameters(client_peer['secret_key'], server_msg, client_peer['cipher'])
                #mensagem que pretendemos pedir
                msg = {"type": "client-disconnect", "src": self.client.id, "dst": src_id,
                       "data": {"cipher-msg": cipher_msg, "salt-cipher": salt_cipher, "salt-hash": salt_hash, "IV": IV_sending1, "phase": phase+1}}
                new_msg = json.dumps(msg)
                #cifragem da mensagem
                (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
                sec = {"type": "secure",
                       "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                       "payload": {"msg": msg_c}}
                data = json.dumps(sec)
                self.client.sock.send(data + "\n\n")
                self.client.delete_clients[src_id] = 'lixo'
                logging.info("\n\nThe client " + src_id + "has been disconnected!")
                return

            else:
                logging.warning("It's impossible to disconnect because the message isn't from the source\n")
                #apagar as ligacoes ao cliente quebrado
                del self.client.clients_on[src_id]
                #mensagem que pretendemos pedir
                msg = {"name": self.client.name, "type": "connect", "phase": 1, "cipher": self.client.cipher, "id": self.client.id, "data": {}}
                data = json.dumps(msg)
                self.client.sock.send(data + TERMINATOR)
                return

        if phase == 2:
            src_id = server_msg['src']
            self.client.delete_clients[src_id] = 'lixo'
            logging.info("\n\nThe client " + src_id + "has been disconnected!")
            self.client.DisplayOptions()
            return

    def ClientGotRekt(self, request):
        logging.warning("O cliente " + request['dst'] + " nao existe!\n")
        if request['dst'] in self.client.clients_on.keys():
            del self.client.clients_on[request['dst']]
        self.client.GetList()

    def recvAck(self, request):
        '''
            Quando estamos a fazer a troca de mensagens do tipo "client-com", o cliente que envia a mensagem
            tem de receber um ack a dizer que a mensagem foi entregue ao cliente destino.
            Esta funcao gera esses acks e mostra-os ao utilizador.
        :param request: conteudo da mensagem que chegou pelo socket.
        :return:
        '''
        dst_id = request['src']
        if(dst_id not in self.client.delete_clients.keys()) and (dst_id in self.client.clients_on.keys()):
            secret_key = self.client.clients_on[dst_id]['secret_key']
            (hash_new_client, dec_msg_client) = self.DecipherMessage(base64.b64decode(request['data']['IV']),
                                                                     base64.b64decode(request['data']['cipher']),
                                                                     base64.b64decode(request['data']['salt-cipher']),
                                                                     base64.b64decode(request['data']['salt-hash']),
                                                                     secret_key,
                                                                     self.client.clients_on[dst_id]['cipher'])

            if hash_new_client == 'OK':
                print "\n\nA mensagem foi enviada com sucesso para o cliente: " + self.client.clients_on[dst_id]['name']
                return
            else:
                print "\n\nA mensagem nao foi enviada para o cliente: " + self.client.clients_on[dst_id]['name']
                return

    def sendAck(self, request):
        '''
             Quando estamos a fazer troca de mensagens do tipo "client-com", o cliente que recebe a mensagem
             tem de enviar um ack para a source da msg a dizer que a mensagem foi recebida
             Esta funcao gere esses acks e envia para o cliente.
        :param request: conteudo da mensagem que chegou pelo socket.
        :return:
        '''
        dst_id = request['src']

        if(dst_id not in self.client.delete_clients.keys()) and (dst_id in self.client.clients_on.keys()):
            secret_key = self.client.clients_on[dst_id]['secret_key']
            #cifragem da mensagem
            (IV_sending1, cipher_msg, salt_cipher, salt_hash) = self.GenerateCipherParameters(secret_key, "ack", self.client.clients_on[dst_id]['cipher'])
            #mensagem que pretendemos pedir
            msg = {"type": "ack", "src": self.client.id, "dst": dst_id,
                   "data": {"IV": IV_sending1, "cipher-msg": cipher_msg, "salt-cipher": salt_cipher, "salt-hash": salt_hash}}
            new_msg = json.dumps(msg)
            #cifragem da mensagem
            (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
            sec = {"type": "secure",
                   "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
                   "payload": {"msg": msg_c}}
            data = json.dumps(sec)
            self.client.sock.send(data + "\n\n")
            return

    def processRecvMsg(self, server_msg):
        '''
               Esta funcao trata de imprimir as mensagens recebidas do tipo ""client-com" e mostra o nome do cliente que a enviou
               Para termos a certeza que a mensagem nao foi adulterado e vem mesmo do source, temos de decifrar a mensagem e verificar
               se o HMAC que geramos é igual o HMAC enviado pelo source antes da mensagem ter sido cifrada.
               Se os HMAC corresponderem, vamos imprimir a mensagem.
               :param server_msg: conteúdo da mensagem que chegou pelo socket
               :return:
        '''
        src_id = server_msg['src']
        client_peer = self.client.clients_on[src_id]

        (hash_new_client, dec_msg_client) = self.DecipherMessage(base64.b64decode(server_msg['data']['IV']),
                                                                 base64.b64decode(server_msg['data']['cipher']),
                                                                 base64.b64decode(server_msg['data']['salt-cipher']),
                                                                 base64.b64decode(server_msg['data']['salt-hash']),
                                                                 client_peer['secret_key'],
                                                                 client_peer['cipher'])

        if hash_new_client == 'OK':
            logging.info("\n\nMensagem recebida de " + client_peer['name'] + ": %s\n", dec_msg_client)
            client_peer['counter'] += 1
            elapsed_time = time.time() - client_peer['time']
            if elapsed_time > 600:
                self.NewClientKeys(src_id)
            elif client_peer['counter'] >= 20:
                self.NewClientKeys(src_id)
            return
        else:
            logging.warning("\n\nMensagem recebida de " + client_peer['name'] + "foi adulterada!\n Vamos tentar estabelecer uma nova ligacao...")
            msg = {"name": self.client.name, "type": "connect", "phase": 1, "cipher": self.client.cipher, "id": self.client.id, "data": {}}
            data = json.dumps(msg)
            self.client.sock.send(data + TERMINATOR)
            return

    def NewClientKeys(self, id):
        '''
                Esta funcao só é utilizada para começar uma nova geracao de chaves entre dois clientes quando um destes dois fatores e ativado:
                    -> O tempo de conexao foi ultrapassado e e preciso gerar novas chaves
                    -> O numero de mensagens "permitidas" foi ultrapassado e e preciso gerar novas chaves
                Usamos esta funcao porque ja nao e preciso acordar o cipherspec, apenas e preciso gerar novas chaves!
                Devido a esse aspecto, esta mensagem vai ser "forçada" a estar na fase 5 porque tudo o que esta para tras(ciphers) ja foi
                previamente definido.
                :param id: id do cliente que se esta a ligar
                :return:
        '''
        logging.info("\nO tempo ja expirou. Vamos estabelecer uma conexao entre clientes...")
        client_peer = self.client.clients_on[id]
        #chave secreta(alfa)
        peer_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        #chave publica
        peer_public_key = peer_private_key.public_key()

        client_peer['private_key'] = peer_private_key
        client_peer['public_key'] = peer_public_key

        msg = {"type": "client-connect", "src": self.client.id, "dst": id, "phase": 5, "cipher": [client_peer['cipher']],
               "data": {"pub": utilsAES.serializePublicKey(peer_public_key), "name": self.client.name}}
        new_msg = json.dumps(msg)
        #cifragem da mensagem
        (IV_sending, msg_c, salt_cipher, salt_hash) = self.GenerateCipherParameters(self.client.shared_key, new_msg, self.client.cipher)
        sec = {"type": "secure",
               "sa-data": {"IV": IV_sending, "salt-cipher": salt_cipher, "salt-hash": salt_hash},
               "payload": {"msg": msg_c}}
        data = json.dumps(sec)
        self.client.sock.send(data + "\n\n")
        return









