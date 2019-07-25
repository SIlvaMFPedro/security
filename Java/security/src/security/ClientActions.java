    /*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.lang.Thread;
import java.net.Socket;

import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.Security;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.security.auth.callback.CallbackHandler;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;

import java.util.Base64;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


import com.google.gson.*;
import com.google.gson.stream.*;
import java.security.AlgorithmParameters;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;


/**
 *
 * @author pedro
 */
class ClientActions implements Runnable{
       boolean registered = false;
       ClientDescription client;
       
       Socket client_socket;
       JsonReader in;
       OutputStream out;
       ServerControl registry;
       SecretKey secret_key;
       
       Scanner sc = new Scanner(System.in);
       String command = null;
       String client_msg = null;
       String option = null;
       String response = null;
       String msg = null;
       String msg_id = null;
       String rec_id = null;
       String dest = null;
       String username = null;
       String src = null;
       String user_name = null;
       String cc = null;
       String choice = null;
       byte[] iv_server = null;
       byte[] iv_client = null;
       boolean process_msg = false;
       public static boolean sec = false;
       
       static String file = "/opt/bar/cfg/CitizenCard.cfg";
       static Provider prov = new sun.security.pkcs11.SunPKCS11(file);
       static X509Certificate x509_cert = null;
       static Signature sign = null;
       static boolean already_signed = false;
       static X509Certificate other_client_cert = null;

       ClientActions ( Socket c, ServerControl r ) {
           client_socket = c;
           registry = r;

           try {
               in = new JsonReader( new InputStreamReader ( c.getInputStream(), "UTF-8") );
               out = c.getOutputStream();
           } catch (Exception e) {
               System.err.print( "Cannot use client socket: " + e );
               Thread.currentThread().interrupt();
               System.exit(1);
           }
       }
       
       public void setSocket(Socket c){
           client_socket = c;
       }
       
       void printMenu(){
           System.out.println("----------------------------------------------------------------------------");
           System.out.println("********************************** MENU ************************************");
           System.out.println(" (1) - CREATE;   (2) - LIST;     (3) - NEW;      (4) - ALL;                  ");
           System.out.println(" (5) - SEND;     (6) - RECV;     (7) - RECEIPT;  (8) - STATUS;   (9) - EXIT;");
           System.out.println("Input command: \n");
           System.out.print("---> ");
           command = sc.next();
           sc.nextLine();
           if(!command.equals("1") && !command.equals("2") && !command.equals("3") && !command.equals("4") && !command.equals("5") && !command.equals("6") && !command.equals("7") 
                && !command.equals("8") && !command.equals("9") && !command.equalsIgnoreCase("create") && !command.equalsIgnoreCase("list") 
                && !command.equalsIgnoreCase("new") && !command.equalsIgnoreCase("all") && !command.equalsIgnoreCase("send") && !command.equalsIgnoreCase("recv") 
                && !command.equalsIgnoreCase("receipt") && !command.equalsIgnoreCase("status") && !command.equalsIgnoreCase("exit")){
                System.out.println("Invalid command introduced! Please try again...");
                printMenu();
           }
           System.out.println("----------------------------------------------------------------------------");
       }
       
       void insertCommand(String commandLine){
           try{
               //CREATE
               if(commandLine.equals("1") || commandLine.equalsIgnoreCase("CREATE")){
                   System.out.print("Insert the new client ID: ");
                   String client_id = sc.next();
                   sc.nextLine();
                   client_msg = "{\n \"type\": \"create\",\n \"uuid\": " + client_id +" \n }";
                   out.write (client_msg.getBytes( StandardCharsets.UTF_8 ));
                   return;
               }
               //LIST
               if(commandLine.equals("2") || commandLine.equalsIgnoreCase("LIST")){
                   System.out.print("Insert ID [or \"all\"] to list: ");
                   String client_id = sc.next();
                   sc.nextLine();
                   if(client_id.equals("all")){
                        client_msg = "{\n \"type\": \"list\" \n }";
                   }
                   else{
                       client_msg = "{\n \"type\": \"list\",\n \"id\": " + client_id + " \n }";
                   }
                   out.write (client_msg.getBytes( StandardCharsets.UTF_8 ));
                   return;
               }
               //NEW
               if(commandLine.equals("3") || commandLine.equalsIgnoreCase("NEW")){
                   client_msg = "{\n \"type\": \"new\",\n \"id\": " + Client.client_id +" \n }";
                   out.write (client_msg.getBytes( StandardCharsets.UTF_8 ));
                   return;
               }
               //ALL
               if(commandLine.equals("4") || commandLine.equalsIgnoreCase("ALL")){
                   client_msg = "{\n \"type\": \"all\",\n \"id\":" + Client.client_id + " \n }";
                   out.write (client_msg.getBytes( StandardCharsets.UTF_8 ));
                   return;
               }
               //SEND
               if(commandLine.equals("5") || commandLine.equalsIgnoreCase("SEND")){
                   executeSend();
                   return;
               }
               //RECV
               if(commandLine.equals("6") || commandLine.equalsIgnoreCase("RECV")){
                   if(sec == false){
                       System.err.println("ERROR! You are not in a secure connection yet!");
                   }
                   else{
                       System.out.println("Insert message ID[ srcID_msgID ]:  ");
                       msg_id = sc.next();
                       System.out.println("Input ID: ");
                       String client_id = sc.next();
                       System.out.println("Insert ID of message author: ");
                       src = sc.next();
                       System.out.println("Input username of message author: ");
                       user_name = sc.next();
                       System.out.println("Is the message signed?(Y/N) ");
                       cc = sc.next();
                       if(cc.equalsIgnoreCase("Y")){
                           String cipher_msg = "{\"type\": \"recv\",\"id\": " + client_id + ",\"msg\": " + msg_id  + ",\"auth\": " + src + ",\"authname\": " + user_name + ",\"recv\": \"SUCCESS!\"}";
                           byte[] hmac = getHMAC(cipher_msg, Client.server_sym_key);
                           byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", cipher_msg, "sym", "server");
                           if(Client.sign_prompt.equals("Y")){
                               byte[] signature = signMessage(cipher_msg);
                               client_msg = "{\"type\":\"recv\",\"Signature\":\""+ Base64.getEncoder().encodeToString(signature) + "\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"data\":\"" + Base64.getEncoder().encodeToString(msg_to_send) +  "\",\"iv\":\"" + Base64.getEncoder().encodeToString(iv_server) +  "\",\"uuid\":\"" + Client.client_id + "\"}";
                           }
                       }
                       else{
                           client_msg = "{\"type\": \"recv\",\"id\": \"" + Client.client_id + "\",\"msg\": \"" + msg_id +"\",\"recv\": \"FAILURE!\"\n }";
                        }
                   }
                   out.write (client_msg.getBytes( StandardCharsets.UTF_8 ));
                   return;
               }
               //RECEIPT
               if(commandLine.equals("7") || commandLine.equalsIgnoreCase("RECEIPT")){
                   if(sec == false){
                         System.err.println("ERROR! You are not in a secure connection yet!");
                   }
                   else{
                        System.out.println("Current client ID of the message box: " + Client.client_id);
                        System.out.println("Insert message ID to confirm the receipt: ");
                        rec_id = sc.next();
                        System.out.println("Insert ID of receipt author: ");
                        src = sc.next();
                        System.out.println("Input username of receipt author");
                        user_name = sc.next();
                        System.out.println("Is the receipt signed?(Y/N)");
                        cc = sc.next();
                        sc.nextLine();
                        if(cc.equalsIgnoreCase("Y")){
                            String cipher_msg = "{\"type\": \"receipt\",\"id\": " + Client.client_id + ",\"msg\": " + rec_id + ",\"auth\": " + src + ",\"authname\": " + user_name + "\",\"receipt\": \"SUCCESS!\"\n }";
                            byte[] hmac = getHMAC(cipher_msg, Client.server_sym_key);
                            byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", cipher_msg, "sym", "server");
                            if(Client.sign_prompt.equals("Y")){
                                byte[] signature = signMessage(cipher_msg);
                                client_msg = "{\"type\":\"receipt\",\"Signature\":\""+ Base64.getEncoder().encodeToString(signature) + "\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"data\":\"" + Base64.getEncoder().encodeToString(msg_to_send) +  "\",\"iv\":\"" + Base64.getEncoder().encodeToString(iv_server) +  "\",\"uuid\":\"" + Client.client_id + "\"}";
                                System.out.println(client_msg);
                            }
                        }
                        else{
                            client_msg = "{\n\"type\": \"receipt\",\n\"id\": \"" + Client.client_id + "\",\n\"msg\": \"" + rec_id +"\",\n\"receipt\": \"FAILURE!\"\n }";
                            
                        }
                        out.write(client_msg.getBytes( StandardCharsets.UTF_8 ));
                   }
                   return;
               }
               //STATUS
               if(commandLine.equals("8") || commandLine.equalsIgnoreCase("STATUS")){
                   System.out.print("Current client ID of the receipt box: " + Client.client_id);
                   System.out.print("Insert message ID to confirm the receipt: " );
                   String id = sc.next();
                   sc.nextLine();
                   if(id.equalsIgnoreCase(msg_id)){
                      client_msg =  "{\n \"type\": \"status\",\n \"id\": " + Client.client_id + ",\n \"msg\": "+ id + "\",\n\"status\": \"SUCCESS!\"\n}";
                      out.write(client_msg.getBytes( StandardCharsets.UTF_8 ));
                   }
                   else{
                      client_msg =  "{\n \"type\": \"status\",\n \"id\": " + Client.client_id + ",\n \"msg\": "+ id + "\",\n\"status\": \"FAILURE!\"\n}";
                      out.write(client_msg.getBytes( StandardCharsets.UTF_8 ));
                   }
                   return;
               }
               //EXIT
               if(commandLine.equals("9") || commandLine.equalsIgnoreCase("EXIT")){
                   System.out.print("EXIT! System shutting down...\n");
                   sec = false;
                   client_msg =  "{\n \"type\": \"exit\",\n \"id\": " + Client.client_id + ",\n\"status\": \"SHUTTING DOWN!!\"\n}";
                   out.write(client_msg.getBytes( StandardCharsets.UTF_8 ));
                   try{
                       client_socket.close();  //close socket;
                   }catch(Exception e){
                       System.err.println("Error! System cannot shut down properly! " + e);
                   }
               }          
           }catch(Exception e){
               System.exit(2);
           }
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       void executeSend(){
           try{
               System.out.println("Input message command: ");
               boolean flag = true;
               while(flag){
                   //System.out.println("Begin while!");
                   out = client_socket.getOutputStream();
                   option = sc.next();
                   switch(option){
                       case "connect":
                           System.out.println("Client ID: ");
                           Client.client_id = sc.next();
                           System.out.println("Client Name: ");
                           Client.client_name = sc.next();
                           System.out.println("Do you want to sign client messages?(Y/N): ");
                           Client.sign_prompt = sc.next();
                           if(Client.sign_prompt.equals("Y")){
                               client_msg = "{\"type\":\"connect\",\"phase\":1,\"name\":"+ Client.client_name +",\"uuid\":" + Client.client_id + ",\"ciphers\":[\"RSA\",\"AES\"],\"data\":\"Signed\",\"question\":\"Port/IP\"}";
                           }
                           else{
                               client_msg = "{\"type\":\"connect\",\"phase\":1,\"name\":"+ Client.client_name +",\"uuid\":" + Client.client_id + ",\"ciphers\":[\"RSA\",\"AES\"],\"data\":\"Not Signed\"}";
                           }
                           out.write(client_msg.getBytes(StandardCharsets.UTF_8));
                           flag = false;
                           break;
                       case "client-connect":
                           if(sec == false){
                               System.err.println("ERROR! You are not in a secure connection yet!");
                           }
                           else{
                               System.out.println("With which user do you want to connect to? ");
                               dest = sc.next();
                               System.out.println("What is the username? ");
                               username = sc.next();
                               System.out.println("Does the user use a citizen card?(Y/N) ");
                               cc = sc.next();
                               if(cc.equalsIgnoreCase("Y")){
                                    String cipher_msg = "{\"type\":\"client-connect\",\"inner-sig\":\"\",\"inner-cert\":\"\",\"inner-sdata\":\"\",\"dst\"=\"" + dest + "\",\"name\"=\"" + username +  "\",\"src\"=\"" + Client.client_id + "\",\"phase\"=\"1\",\"ciphers\":[\"RSA\",\"AES\"], \"data\"=\"JSON\"}";
                                    byte[] hmac = getHMAC(cipher_msg, Client.server_sym_key);
                                    byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", cipher_msg, "sym", "server");
                                    if(Client.sign_prompt.equals("Y")){
                                        byte[] signature = signMessage(cipher_msg);
                                        client_msg = "{\"type\":\"secure\",\"Signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\",\"sa-data\":\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\":\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_server) + "\"}";
                                    }
                               }
                               else{
                                   System.err.println("ERROR! In order to establish connection both users need to use their citizen card!");
                                   String error = "Cannot establish connection with this user!";
                                   client_msg = "{\"type\":\"client-connect\", \"dst\"=\"" + dest + "\",\"error\"=\"" + error;
                               }
                               out.write(client_msg.getBytes(StandardCharsets.UTF_8));
                           }
                           flag = false;
                           break;
                       case "client-com":
                           if(sec == false){
                               System.out.println("ERROR! You are not in a secure connection yet!");
                           }
                           else if(Client.client_connected == false){
                               System.err.println("ERROR! You cannot start a communication if you don't have the other client's public key");
                           }
                           else{
                               System.out.println("You wish to start a client-communication with another client!");
                               System.out.println("Input client ID: ");
                               dest = sc.next();
                               if(!dest.equalsIgnoreCase(Client.connected_client_id)){
                                   System.err.println("ERROR! You don't have this client's public key yet!");
                                   String error = "Cannot compute message!";
                                   client_msg = "{\"type\":\"client-com\", \"dst\"=\"" + dest + "\",\"error\"=\"" + error;
                                   break;
                               }
                               System.out.println("Input client username: ");
                               username = sc.next();
                               System.out.println("Input message: ");
                               msg = sc.next();
                               String cipher_msg = null;
                              
                               byte[] signature_msg;
                               byte[] signature_key;
                               byte[] hmac = getHMAC(msg, Client.client_sym_key);
                               byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", msg, "sym", "client");
                               String secret = Base64.getEncoder().encodeToString(Client.client_sym_key.getEncoded());
                               byte[] key_msg_send = cipherMessage("RSA", secret, "asym", "client");
                               byte[] key_rec_send = cipherMessage("RSA", secret, "asym", "receipt");
                               if(Client.sign_prompt.equals("Y")){
                                   signature_msg = signMessage(msg);
                                   signature_key = signMessage(secret);
                                   cipher_msg = "{\"type\":\"client-com\",\"inner-msg-sig\":\"" + Base64.getEncoder().encodeToString(signature_msg) + "\",\"inner-sdata\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"dst\"=\"" + dest + "\",\"name\"=\"" + username + "\",\"src\":\"" + Client.client_id  + "\",\"data\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_client) + "\",\"inner-key-sig\":\"" + Base64.getEncoder().encodeToString(signature_key) + "\",\"key_msg\"=\"" + Base64.getEncoder().encodeToString(key_msg_send) + "\",\"key_rec\"=\"" + Base64.getEncoder().encodeToString(key_rec_send) + "\"}";
                               }
                               else{
                                   System.err.println("ERROR! You need to sign your message!");
                                   break;
                               }
                               hmac = getHMAC(cipher_msg, Client.server_sym_key);
                               msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", cipher_msg, "sym", "server");
                               if(Client.sign_prompt.equals("Y")){
                                   signature_msg = signMessage(cipher_msg);
                                   client_msg = "{\"type\":\"secure\",\"Signature\":\"" + Base64.getEncoder().encodeToString(signature_msg) + "\",\"sa-data\":\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\":\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_server) +  "\"}";
                               }
                               else{
                                    System.err.println("ERROR! You need to sign your message!");
                                    break;
                               }
                               out.write(client_msg.getBytes(StandardCharsets.UTF_8));
                           }
                           flag = false;
                           break;
                       case "client-disconnect":
                           if(sec == false){
                               System.err.println("ERROR! You are not in a secure connection yet!");
                               return;
                           }
                           if(Client.connected_client_id == null){
                               System.err.println("ERROR! You are not connected to any client!");
                               return;
                           }
                           else{
                               byte[] signature = null;
                               String cipher_msg = null;
                               System.out.println("You wish to terminate your connection with " + Client.connected_client_id + ". Do you wish to proceed witb this option?(Y/N)");
                               choice = sc.next();
                               System.out.println("Input connected client username: ");
                               username = sc.next();
                               
                               if(choice.equals("Y")){
                                   String data = "DC";
                                   String result = "{\"type\":\"client-disconnect\",\"dst\"=\"" + Client.connected_client_id  + "\",\"name\"=\"" + username +  "\",\"src\":\"" + Client.client_id  + "\",\"src_name\"=\"" + Client.client_name + "\",\"data\"=\"" + data + "\"}";
                                   byte[] hmac = getHMAC(result, Client.server_sym_key);
                                   byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, "sym", "server");
                                   if(Client.sign_prompt.equals("Y")){
                                       signature = signMessage(result);
                                       System.out.println("Signature X: " + Base64.getEncoder().encodeToString(signature));
                                       client_msg = "{\"type\":\"secure\",\"Signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\",\"sa-data\":\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\":\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_server) + "\"}";
                                   }
                                   else{
                                       System.err.println("ERROR! You need to sign your message!");
                                       break;
                                   }
                                   out.write(client_msg.getBytes(StandardCharsets.UTF_8));
                               }
                           }
                           flag = false;
                           break;
                       case "help":
                       case "?":
                           System.out.println("Messages Allowed by the System:\n\nCONNECT\t\t\tConnect to the server\n\nMessages Required to be connected:\n\n"
							+ "CLIENT-CONNECT\t\tConnect to another client\n"
							+ "CLIENT-DISCONNECT\tBan spam messages  from other clients\n"
							+ "CLIENT-COM\t\tEstablish communication with another client\n");
                           break;     
                   }
                   //System.out.println("End While!");
               }
           }catch(IOException e){
               //Auto generated catch block wtih all exceptions;
               e.printStackTrace();
           }
       }
       
       JsonObject readCommand () {
           try {
               System.out.println("Read Command!");
               JsonElement data = new JsonParser().parse( in );
               if (data.isJsonObject()) {
                   System.out.println("Done reading!!");
                   return data.getAsJsonObject();
               }
               System.err.print ( "Error while reading command from socket (not a JSON object), connection will be shutdown\n" );
               // return null;
           } catch (Exception e) {
               System.err.print ( "Error while reading JSON command from socket, connection will be shutdown\n" );
               System.exit(3);
               // return null;
           }
           System.out.println("Done reading!!");
           return null;
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       void executeCommand(String command, JsonObject data){
            JsonElement cmd = data.get("type");
            ClientDescription me;

            if (command == null) {
                System.err.println ( "Invalid command in request: " + data );
                return;
            }

            // CREATE

            if (command.equals("1") || command.equalsIgnoreCase("CREATE")) {
                
                System.out.println("CREATE");
                Client.client_id = data.getAsJsonObject().get("result").getAsString();
                System.out.println("Client ID: " + Client.client_id);

                if (Client.client_id == null) {
                    System.err.print ( "No \"uuid\" field in \"create\" request: " + data );
                    return;
                }

                if (registry.clientExists( Client.client_id )) {
                    System.err.println ( "Client already exists: " + data );
                    return;
                }

                data.remove ( "type" );
                me = registry.addClient(Client.client_id, data, out );
                return;
            }

            // LIST

            if (command.equals("2") || command.equalsIgnoreCase("LIST")) {
                System.out.println("LIST");
                JsonArray lst = data.getAsJsonArray("data");
                JsonObject obj;
                System.out.println("Client list: " + lst.size() + "\n");
                String list;
                String user = null; // 0 means all users
                
                for(int i = 0; i < lst.size(); i++){
                    obj = lst.get(i).getAsJsonObject();
                    String uuid = obj.get("uuid").getAsString();
                    String id = obj.get("id").getAsString();
                    if(id != null){
                        user = id;
                    }
                    System.out.println( "List " + (user == null ? "all clients" : "client ") + user );
                    list = registry.listClients(user);
                    System.out.println("Client " + (i+1) + ": " + " uuid: " + uuid+ " id: " + user);
                }
                return;
            }

            // NEW

            if (command.equals("3") || command.equalsIgnoreCase("NEW")) {
                System.out.println("NEW");
                JsonArray array = data.getAsJsonArray("result");
                String message_id = null;
                String src_id;
                String dst_id;
                src_id = dst_id = "";
                boolean flag = false;
                for(int i = 0; i < array.size(); i++){
                    message_id = array.get(i).getAsString();
                    src_id = dst_id = "";
                    flag = false;
                    for(int j = 0; j < message_id.length(); j++){
                        if(message_id.charAt(j) == '_'){
                            flag = true;
                            continue;
                        }
                        if(!flag){
                            src_id += msg_id.charAt(j);
                        }
                        else{
                            dst_id += msg_id.charAt(j);
                        }
                    }
                    System.out.println("Unread messages received from source user ID: " + src_id + " with destination message ID: " + dst_id);
                }
            }

            // ALL

            if (command.equals("4") || command.equalsIgnoreCase("ALL")) {
                
                System.out.println("ALL");
                JsonArray array = data.getAsJsonArray("result");
                String message_id = null;
                String src_id = null;
                String dst_id = null;
                src_id = dst_id = "";
                boolean flag = false;
                boolean alreadyRead = false;
                System.out.println("/*----------Messages Received----------*/");
                JsonArray recv_array = array.get(0).getAsJsonArray(); //vamos buscar a primeira parte do array results;
                for(int i = 0; i < recv_array.size(); i++){
                    message_id = recv_array.get(i).getAsString();
                    src_id = dst_id = "";
                    flag = alreadyRead = false;
                    for(int j = 0; j < message_id.length(); j++){
                        if(message_id.charAt(0) == '_' && !alreadyRead){
                            alreadyRead = true;
                            continue;
                        }
                        if(message_id.charAt(j) == '_'){
                            flag = true;
                            continue;
                        }
                        if(!flag){
                            src_id += message_id.charAt(j);
                        }
                        else{
                            dst_id += message_id.charAt(j);
                        }
                        if(alreadyRead){
                            System.out.println("Messages received from source user ID: " + src_id + " with destination message ID: " + dst_id);
                        }
                        else{
                            System.out.println("Unread messages received from source user ID: " + src_id + " with destination message ID: " + dst_id);
                        }
                    }
                }
                System.out.println("/*----------Messages Sent-------------*/");
                JsonArray sent_array = array.get(0).getAsJsonArray(); //vamos buscar a segunda parte do array results;
                for(int i = 0; i < sent_array.size(); i++){
                    message_id = sent_array.get(i).getAsString();
                    src_id = dst_id = "";
                    flag = false;
                    for(int j = 0; j < message_id.length(); j++){
                        if(message_id.charAt(j) == '_'){
                            flag = true;
                            continue;
                        }
                        if(!flag){
                            src_id += message_id.charAt(j);
                        }
                        else{
                            dst_id += message_id.charAt(j);
                        }
                    }
                    System.out.println("Messages sent from source user ID:  " + src_id + " with destination message ID: " + dst_id);
                }
                return;
            }

            // SEND

            if (command.equals("5") || command.equalsIgnoreCase("SEND")) {
                System.out.println("SEND");
                try{
                    processMessage(data); //O cliente para percorrer as fases tem de mandar uma mensagem connect ao servidor -> não chega à fase 6!
                }catch(IOException e){
                    System.err.println("Error! Cannot process message exception: " + e); 
                }
                return;
               
            }

            // RECV

            if (command.equals("6") || command.equalsIgnoreCase("RECV")) {
                System.out.println("RECV");
                JsonElement sub_data = data.get("data");
                JsonElement iv_data = data.get("iv");
                JsonElement sa_data = data.get("sa-data");
                byte[] byte_array = Base64.getDecoder().decode(sub_data.getAsString());
                byte[] iv_array = Base64.getDecoder().decode(iv_data.getAsString());
                byte[] ack = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym", "server");
             
                String str = new String();
                try{
                    str = new String(ack, "UTF8");
                }catch(UnsupportedEncodingException e){
                    //Auto generated block with all exceptions
                    e.printStackTrace();
                }
                byte[] hmac = getHMAC(str, Client.server_sym_key);
                if(!(Base64.getEncoder().encodeToString(hmac).equals(sa_data.getAsString()))){
                    System.err.println("Error! The server has been compromised!");
                    return;
                }
                
                JsonObject payload;
                payload = new JsonParser().parse(str).getAsJsonObject();
                
                JsonElement info = payload.get("result");
                JsonElement cert = payload.get("cert");
                
                JsonObject infoload;
                infoload = new JsonParser().parse(info.getAsString()).getAsJsonObject();
                
                JsonElement dst = infoload.get("DST");
                JsonElement src_id = infoload.get("SRC");
                JsonElement name = infoload.get("NAME");
                JsonElement msg_sign = infoload.get("MSG_SIGN");
                JsonElement msg_hmac = infoload.get("MSG_HMAC");
                JsonElement msg_data = infoload.get("MSG_DATA");
                JsonElement msg_iv = infoload.get("IV");
                JsonElement key_sign = infoload.get("KEY_SIGN");
                JsonElement key = infoload.get("KEY");
                
                byte[] key_info = Base64.getDecoder().decode(key.getAsString());
                byte[] decodedkey = decipherMessage("RSA", key_info, null, "asym", "client");
                byte[] k_array = Base64.getDecoder().decode(decodedkey);
                
                SecretKey originalKey = new SecretKeySpec(k_array, 0, k_array.length, "AES");
                Client.client_sym_key = originalKey;
                String tst = Base64.getEncoder().encodeToString(originalKey.getEncoded());
                String signature = msg_sign.getAsString();
                System.out.println("SIGN: " + signature);
                String certificate = cert.getAsString();
                System.out.println("CERT: " + certificate);
                
                if(Client.sign_prompt.equals("Y")){
                    if(!(msg_sign.getAsString().equals("")) && !(cert.getAsString().equals(""))){
                        System.out.println("Certificado: " + cert.toString());
                        X509Certificate x509_tmp = null;
                        byte[] c_array = Base64.getDecoder().decode(cert.getAsString());
                        InputStream bin = new ByteArrayInputStream(c_array);
                        CertificateFactory factory;
                        try{
                            factory = CertificateFactory.getInstance("X.509");
                            x509_tmp = (X509Certificate) factory.generateCertificate(bin);
                            if(validateCertificate(x509_tmp)){
                                other_client_cert = x509_tmp;
                                byte[] s_array = Base64.getDecoder().decode(msg_sign.getAsString());
                                if(validateSignature(other_client_cert, tst, s_array)){
                                    System.out.println("SUCCESS! VALID SIGNATURE!");
                                }
                                else{
                                    System.err.println("ERROR! INVALID SIGNATURE!");
                                }
                            }
                            else{
                                System.err.println("ERROR! INVALID CERTIFICATE!");
                                return;
                            }
                        }catch(CertificateException e){
                            //Auto-generated catch block with all exceptions;
                        }
                    }
                }
                
               byte[] recv_msg = Base64.getDecoder().decode(msg_data.getAsString());
               byte[] iv = Base64.getDecoder().decode(msg_iv.getAsString());
               byte[] decoded_msg = decipherMessage("AES/CTR/PKCS5Padding", recv_msg, iv, "sym", "client");
               
               String decoded = new String();
               try{
                    decoded = new String(decoded_msg, "UTF8");
                }catch(UnsupportedEncodingException e){
                    //Auto generated block with all exceptions
                    e.printStackTrace();
                }
                byte[] hmac_d = getHMAC(decoded, Client.client_sym_key);
                if(!(Base64.getEncoder().encodeToString(hmac_d).equals(msg_hmac.getAsString()))){
                    System.err.println("Error! The message has been compromised!");
                    return;
                }
                System.out.print("Dst: " + dst.getAsString() + "Name: " + name.getAsString() + "Src: " + src_id.getAsString() + "Received Message: " + decoded);
                System.out.println("End of message decoding...");
                return;
                
            }

            // RECEIPT

            if (command.equals("7") || command.equalsIgnoreCase("RECEIPT")) {
                System.out.println("RECEIPT");
                JsonElement sub_data = data.get("data");
                JsonElement iv_data = data.get("iv");
                JsonElement sa_data = data.get("sa-data");
                byte[] byte_array = Base64.getDecoder().decode(sub_data.getAsString());
                byte[] iv_array = Base64.getDecoder().decode(iv_data.getAsString());
                byte[] ack = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym", "server");
             
                String str = new String();
                try{
                    str = new String(ack, "UTF8");
                }catch(UnsupportedEncodingException e){
                    //Auto generated block with all exceptions
                    e.printStackTrace();
                }
                byte[] hmac = getHMAC(str, Client.server_sym_key);
                if(!(Base64.getEncoder().encodeToString(hmac).equals(sa_data.getAsString()))){
                    System.err.println("Error! The server has been compromised!");
                    return;
                }
                
                JsonObject payload;
                payload = new JsonParser().parse(str).getAsJsonObject();
                
                JsonElement info = payload.get("result");
                payload = new JsonParser().parse(str).getAsJsonObject();
                
                JsonElement dst = payload.get("DST");
                JsonElement src_id = payload.get("SRC");
                JsonElement name = payload.get("NAME");
                JsonElement msg_sign = payload.get("MSG_SIGN");
                JsonElement msg_hmac = payload.get("MSG_HMAC");
                JsonElement msg_data = payload.get("MSG_DATA");
                JsonElement msg_iv = payload.get("IV");
                JsonElement key_sign = payload.get("KEY_SIGN");
                JsonElement key = payload.get("KEY");
                
                byte[] key_info = Base64.getDecoder().decode(key.getAsString());
                byte[] decodedkey = decipherMessage("RSA", key_info, null, "asym", "receipts");
                byte[] k_array = Base64.getDecoder().decode(decodedkey);
                
                SecretKey originalKey = new SecretKeySpec(k_array, 0, k_array.length, "AES");
                Client.client_sym_key = originalKey;
                String tst = Base64.getEncoder().encodeToString(originalKey.getEncoded());
                System.out.println("SK: " + tst);
                String signature = msg_sign.getAsString();
                System.out.println("SIGN: " + signature);
                String certificate = x509_cert.toString();
                System.out.println("CERT: " + certificate);
                
                if(Client.sign_prompt.equals("Y")){
                    if(!(msg_sign.getAsString().equals("")) && !(x509_cert.toString().equals(""))){
                        System.out.println("Certificado: " + x509_cert.toString());
                        X509Certificate x509_tmp = null;
                        byte[] c_array = Base64.getDecoder().decode(certificate);
                        InputStream bin = new ByteArrayInputStream(c_array);
                        CertificateFactory factory;
                        try{
                            factory = CertificateFactory.getInstance("X.509");
                            x509_tmp = (X509Certificate) factory.generateCertificate(bin);
                            if(validateCertificate(x509_tmp)){
                                x509_cert = x509_tmp;
                                byte[] s_array = Base64.getDecoder().decode(msg_sign.getAsString());
                                if(validateSignature(x509_cert, tst, s_array)){
                                    System.out.println("SUCCESS! VALID SIGNATURE!");
                                }
                                else{
                                    System.err.println("ERROR! INVALID SIGNATURE!");
                                }
                            }
                            else{
                                System.err.println("ERROR! INVALID CERTIFICATE!");
                                return;
                            }
                        }catch(CertificateException e){
                            //Auto-generated catch block with all exceptions;
                        }
                    }
                }
              
                byte[] recv_msg = Base64.getDecoder().decode(msg_data.getAsString());
                byte[] iv = Base64.getDecoder().decode(msg_iv.getAsString());
                byte[] decoded_msg = decipherMessage("AES/CTR/PKCS5Padding", recv_msg, iv, "sym", "client");
               
                String decoded = new String();
                try{
                    decoded = new String(decoded_msg, "UTF8");
                }catch(UnsupportedEncodingException e){
                    //Auto generated block with all exceptions
                    e.printStackTrace();
                }
                byte[] hmac_d = getHMAC(decoded, Client.client_sym_key);
                if(!(Base64.getEncoder().encodeToString(hmac_d).equals(msg_hmac.getAsString()))){
                    System.err.println("Error! The message has been compromised!");
                    return;
                }
                System.out.print("Dst: " + dst.getAsString() + "Name: " + name.getAsString() + "Src: " + src_id.getAsString() + "Msg: " + payload.get("msg").getAsString() + "Receipt Message: " + decoded);
                System.out.println("End of message receipt...");
                
                return;
            }

            // STATUS

            if (command.equals("8") || command.equalsIgnoreCase("STATUS")) {
                System.out.println("STATUS");
                JsonObject obj = data.getAsJsonObject("result");
                JsonElement status_msg = obj.get( "msg" );
                JsonArray receipts = obj.getAsJsonArray("receipts");
                for(int i = 0; i < receipts.size(); i++){
                    JsonObject receipt = receipts.get(i).getAsJsonObject();
                    String date = receipt.get("date").getAsString();
                    String id = receipt.get("id").getAsString();
                    String rec = receipt.get("receipt").getAsString();
                    if(id == null || status_msg == null){
                        System.err.print ( "Badly formated \"status\" request: " + data );
                        return;
                    }
                    int fromId = Integer.parseInt(id);
                    if(registry.copyExists(fromId, status_msg.getAsString()) == false){
                        System.err.print ( "Unknown message for \"status\" request: " + data );
                        return;
                    }
                    System.out.println("Message: " + status_msg.getAsString() + "\nDate: " + date + "\nID: " + id + "\nReceipt: " + rec + "\n");
                }
            }
            else{
                System.out.println("\"Unknown request\"" );
            }
           
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       void processMessage(JsonObject data) throws IOException{
           System.out.println("Processing message...\n");
           JsonElement server_port = data.get("port");
           JsonElement server_ip = data.get("ip");
           if(!server_port.getAsString().equals("8080") || !server_ip.getAsString().equals("127.0.0.1")){
               System.err.println("Invalid server response! End connection");
                client_msg =  "{\n \"type\": \"exit\",\n \"id\": " + Client.client_id + ",\n\"status\": \"SHUTTING DOWN!!\"\n}";
                out.write(client_msg.getBytes( StandardCharsets.UTF_8 ));
                try{
                      client_socket.close();  //close socket;
                }catch(Exception e){
                      System.err.println("Error! System cannot shut down properly! " + e);
                }
           }
           
           JsonElement cmd = data.get("type");
           //check if command is null
           if(cmd == null){
               System.err.println("Error! Invalid command in the message: " + data);
               return;
           }
           //connect;
           if(cmd.getAsString().equals("connect")){
               JsonElement phase = data.get("phase");
               if(phase == null){
                   System.err.println("Error! No \\\"phase\\\" field in message: " + data);
                   return;
               }
               process_msg = true;
               switch (phase.getAsInt()) {
                   case 2:
                       {
                           System.out.println("Begin phase02");
                           JsonElement server_msg = data.get("data");
                           if(!server_msg.getAsString().equals("OK")){
                               System.err.println("Invalid server response. You cannot start connection with the server. Breaking down the connection process!");
                           }
                           else{
                               PublicKey public_key = createKeys("RSA", "server");
                               String cmd_msg = Base64.getEncoder().encodeToString(public_key.getEncoded());
                               response = "{\"type\":\"connect\",\"phase\":3,\"name\":"+ Client.client_name + ",\"uuid\":\"" + Client.client_id + "\",\"ciphers\":[\"RSA\",\"AES\"],\"data\":\""+ cmd_msg +"\"}";
                               out.write(response.getBytes(StandardCharsets.UTF_8));
                               System.out.println("End phase02");
                           }
                           break;
                       }
                   case 4:
                       {
                           //criar uma chave simétrica da sessao e ciframos com a chave publica do server e enviamos a mensagem para o server;
                           System.out.println("Begin phase04");
                           JsonElement key_data = data.get("data");
                           byte[] cert = null;
                           byte[] byte_array = Base64.getDecoder().decode(key_data.getAsString());
                           X509EncodedKeySpec key_spec = new X509EncodedKeySpec(byte_array);
                           KeyFactory factory;
                           
                           try{
                               factory = KeyFactory.getInstance("RSA");
                               Client.server_public_key = factory.generatePublic(key_spec);
                           }catch(NoSuchAlgorithmException | InvalidKeySpecException e){
                               //Auto-generated catch block with all exceptions;
                               e.printStackTrace();
                           }       
                           SecretKey sym_key = symKey("AES", "server");
                           Client.server_sym_key = sym_key;
                           String cmd_msg = Base64.getEncoder().encodeToString(sym_key.getEncoded());
                           byte[] cipher_txt = cipherMessage("RSA", cmd_msg, "asym", "server");
                           if(Client.sign_prompt.equals("Y")){
                               byte[] client_sign = signMessage(cmd_msg);
                               try{
                                   cert = x509_cert.getEncoded();
                               }catch(CertificateEncodingException e){
                                   //Auto generated catch block with all exceptions
                                   e.printStackTrace();
                               }
                               response = "{\"type\":\"connect\",\"phase\":5,\"name\":"+ Client.client_name + ",\"Certificate\":\"" + Base64.getEncoder().encodeToString(cert) + "\",\"Signature\":\"" + Base64.getEncoder().encodeToString(client_sign) + "\",\"uuid\":\""+ Client.client_id + "\",\"ciphers\":[\"RSA\",\"AES\"],\"data\":\"" + Base64.getEncoder().encodeToString(cipher_txt) + "\"}";
                           }
                           else{
                               response = "{\"type\":\"connect\",\"phase\":5,\"name\":"+ Client.client_name + ",\"Certificate\":\"\",\"Signature\":\"\",\"uuid\":\"" + Client.client_id + "\",\"ciphers\":[\"RSA\",\"AES\"],\"data\":\"" + Base64.getEncoder().encodeToString(cipher_txt) + "\"}";
                           }
                           out.write(response.getBytes(StandardCharsets.UTF_8));
                           System.out.println("End phase04");
                           break;
                       }
                   case 6:
                       {
                           System.out.println("Begin phase06");
                           JsonElement sub_data = data.get("data");
                           JsonElement iv_data = data.get("iv");
                           byte[] byte_array = Base64.getDecoder().decode(sub_data.getAsString());
                           byte[] iv_array = Base64.getDecoder().decode(iv_data.getAsString());
                           byte[] ack = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym", "server");
                           String str = new String(ack, "UTF8");
                           if(str.equals("OK")){
                               System.out.println("The connection to the server has been established!\n");
                               sec = true;
                               process_msg = false;
                           }
                           System.out.println("End phase06");
                           break;
                       }
                   default:
                       break;
               }
           }
           else{
               System.out.println("Secure connection");
               String str = null;
               byte[] byte_array = Base64.getDecoder().decode(data.get("payload").getAsString().getBytes(StandardCharsets.UTF_8));
               byte[] iv_array = Base64.getDecoder().decode(data.get("iv").getAsString().getBytes(StandardCharsets.UTF_8));
               byte[] pay_load = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym", "server");
               try{
                   str = new String(pay_load, "UTF8");
               }catch(UnsupportedEncodingException e){
                   //Auto-generated catch block
                   e.printStackTrace();
               }
               byte[] hmac = getHMAC(str, Client.server_sym_key);
               JsonElement sa_data = data.get("sa-data");
               
               if(!(Base64.getEncoder().encodeToString(hmac).equals(sa_data.getAsString()))){
                   System.err.println("ERROR! The server has been compromised!");
                   return;
               }
               System.out.println("payload: " + str);
               JsonObject payload;
               payload = new JsonParser().parse(str).getAsJsonObject();
               JsonElement inner_cmd;
               inner_cmd = payload.get("type");
               
               //CLIENT-CONNECT
               switch (inner_cmd.getAsString()) {
                   case "client-connect":
                       process_msg = true;
                       byte[] signature = null;
                       byte[] certificate = null;
                       JsonElement client_phase = payload.get("phase");
                       switch (client_phase.getAsInt()) {
                           case 0:
                           {
                               System.err.println("Error: " + payload.get("data").getAsString());
                               break;
                           }
                           case 2:
                           {
                               System.out.println("Begin PHASE02");
                               JsonElement key_data = payload.get("data");
                               byte[] tmp = Base64.getDecoder().decode(key_data.getAsString());
                               X509EncodedKeySpec key_spec = new X509EncodedKeySpec(tmp);
                               KeyFactory factory;
                               try{
                                   factory = KeyFactory.getInstance("RSA");
                                   Client.client_public_key = factory.generatePublic(key_spec);
                               }catch(NoSuchAlgorithmException | InvalidKeySpecException e){
                                   //Auto-generated catch block with all exceptions;
                                   e.printStackTrace();
                               }
                               SecretKey sym_key = symKey("AES", "client");
                               Client.client_sym_key = sym_key;
                               String cmd_msg = "OK";
                               response = "{\"type\":\"client-connect\",\"inner-sdata\":\"\",\"dst\"=\"" + payload.get("dst").getAsString() + "\",\"name\"=\"" + payload.get("name").getAsString() + "\",\"src\"=\"" + payload.get("src").getAsString() + "\",\"phase\"=\"3\", \"data\"=\"" + cmd_msg + "\"}";
                               byte[] hmac_2 = getHMAC(response, Client.server_sym_key);
                               byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", response, "sym", "server");
                               if(Client.sign_prompt.equals("Y")){
                                   signature = signMessage(response);
                                   response = "{\"type\":\"secure\",\"Signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac_2) + "\",\"payload\":\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_server) +"\"}";
                               }
                               else{
                                   System.err.println("ERROR! In order to establish connection both users need to use their citizen card!");
                                   String error = "Cannot establish connection with this user!";
                                   response = "{\"type\":\"client-connect\", \"dst\"=\"" + dest + "\",\"error\"=\"" + error;
                               }
                               out.write(response.getBytes(StandardCharsets.UTF_8));
                               System.out.println("End PHASE02");
                               break;
                           }
                           case 4:
                           {
                               System.out.println("Begin PHASE04");
                               JsonElement msg_data = payload.get("data");
                               if(msg_data.getAsString().equals("OK")){
                                    System.out.println("OK! The connection has been established!");
                                    process_msg = false;
                                    Client.client_connected = true;
                                    Client.connected_client_id = payload.get("dst").getAsString();
                               }
                               else{
                                    System.err.println("Error! The connection has been lost!");
                                    return;
                               }
                               System.out.println("End PHASE04");
                               break;
                           }
                           default:
                               break;
                       }
                   break;
                   case "client-disconnect":
                   {
                        process_msg = true;
                        JsonElement sub_data = payload.get("result");
                        String dc = sub_data.getAsString();
                        //check message
                        if(dc.equalsIgnoreCase("dc") && Client.client_connected == true){
                            System.out.println("The connection established with " + payload.get("dst").getAsString() + " has been terminated!");
                            Client.client_connected = false;
                            Client.connected_client_id = null;
                            Client.client_private_key = null;
                            Client.client_public_key = null;
                            Client.client_sym_key = null;
                        }
                        else{
                            System.err.println("The connection established with " + payload.get("dst").getAsString() + " has already been terminated!");
                            Client.client_connected = false;
                            Client.connected_client_id = null;
                            Client.client_private_key = null;
                            Client.client_public_key = null;
                            Client.client_sym_key = null;
                        }
                        process_msg = false;
                        break;
                   }
                   case "client-com":
                   {
                       process_msg = true;
                       JsonElement msg_data = payload.get("data");
                       if(msg_data.getAsString().equals("OK")){
                            System.out.println("OK! The message has been sent!");
                       }
                       else{
                           System.err.println("Error! Message has been lost during transmission!");
                       }
                       process_msg = false;
                       break;
                   }
                   default:
                       break;
               }
           }
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       static byte[] signMessage(String in){
                System.out.println("Signing message...");
		byte[] signed_hash = null;
		if (already_signed == false){
			Security.addProvider(prov);
			
		}
		CallbackHandler callback_handler = new com.sun.security.auth.callback.TextCallbackHandler();
		KeyStore.Builder build = KeyStore.Builder.newInstance("PKCS11", prov, new KeyStore.CallbackHandlerProtection(callback_handler));
		
		KeyStore key_store;
		try {
			key_store = build.getKeyStore();
			
			String sign_cert_label = "CITIZEN AUTHENTICATION CERTIFICATE";
			sign = Signature.getInstance("SHA1withRSA");
			//char[] pass = "1111".toCharArray();
			sign.initSign((PrivateKey) key_store.getKey(sign_cert_label, null)); 
			sign.update(in.getBytes(StandardCharsets.UTF_8));
                        signed_hash = sign.sign();
                        already_signed = true;
                        x509_cert = (X509Certificate)key_store.getCertificate(sign_cert_label);
		} catch (KeyStoreException | NoSuchAlgorithmException | InvalidKeyException | UnrecoverableKeyException | SignatureException e) {
			//Auto generated catch block with all exceptions;
			e.printStackTrace();
		}
		return signed_hash;
	}
       
       @SuppressWarnings("CallToPrintStackTrace")
       byte[] cipherMessage(String alg, String input, String type, String src){
           byte[] cipher_msg = null;
           //check message type;
           if(type.equals("asym")){
               try{
                   Cipher cipher = Cipher.getInstance(alg);
                   if(src.equals("server")){
                       cipher.init(Cipher.ENCRYPT_MODE, Client.server_public_key);
                       
                   }
                   else if(src.equals("client")){ //client messages
                       cipher.init(Cipher.ENCRYPT_MODE, Client.client_public_key);
                   }
                   else if(src.equals("receipt")){ //client receipts;
                       cipher.init(Cipher.ENCRYPT_MODE, x509_cert.getPublicKey());
                   }
                   cipher_msg = cipher.doFinal(input.getBytes());
               }catch(NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e){
                   //Auto-generated catch block with all exceptions;
                   e.printStackTrace();
               }
           }
           else if(type.equals("sym")){
               try{
                   Cipher cipher = Cipher.getInstance(alg);
                   if(src.equals("server")){
                       cipher.init(Cipher.ENCRYPT_MODE, Client.server_sym_key);
                       AlgorithmParameters params = cipher.getParameters();
                       iv_server = params.getParameterSpec(IvParameterSpec.class).getIV();
                   }
                   else if(src.equals("client")){
                       cipher.init(Cipher.ENCRYPT_MODE, Client.client_sym_key);
                       AlgorithmParameters params = cipher.getParameters();
                       iv_client = params.getParameterSpec(IvParameterSpec.class).getIV();
                   }
                   cipher_msg = cipher.doFinal(input.getBytes("UTF8"));
               }catch(NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidParameterSpecException | UnsupportedEncodingException e){
                   //Auto-generated catch block with all exceptions;
                   e.printStackTrace();
               }
           }
           return cipher_msg;
       }
       @SuppressWarnings("CallToPrintStackTrace")
       byte[] decipherMessage(String alg, byte[] input, byte[] iv, String type, String src){
           byte[] decipher_msg = null;
           if(type.equals("asym")){
               try{
                   if(src.equals("client") || src.equals("receipts")){
                       Cipher decipher = Cipher.getInstance(alg);
                       decipher.init(Cipher.DECRYPT_MODE, x509_cert);
                   }
                   else{
                       Cipher decipher = Cipher.getInstance(alg);
                       decipher.init(Cipher.DECRYPT_MODE, Client.client_private_key);
                       decipher_msg = decipher.doFinal(input);
                   }
               }catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e){
                   //Auto-generated catch block with all exceptions
                   e.printStackTrace();
               }
           }
           else if(type.equals("sym")){
               try{
                   Cipher decipher = Cipher.getInstance(alg);
                   if(src.equals("client")){
                       decipher.init(Cipher.DECRYPT_MODE, Client.client_sym_key, new IvParameterSpec(iv));
                   }
                   else if(src.equals("server")){
                       decipher.init(Cipher.DECRYPT_MODE, Client.server_sym_key, new IvParameterSpec(iv));
                   }
                   decipher_msg = decipher.doFinal(input);
               }catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e){
                   //Auto-generated catch block
                   e.printStackTrace();
               }
           }
           return decipher_msg;
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       byte[] getHMAC(String msg, SecretKey secret_key){
           byte[] hmac = null;
           SecretKeySpec key_spec = new SecretKeySpec(secret_key.getEncoded(), "HmacSHA1");
           try{
               Mac mac = Mac.getInstance("HmacSHA1");
               mac.init(key_spec);
               hmac = mac.doFinal(msg.getBytes());
           }catch(NoSuchAlgorithmException | InvalidKeyException e){
               //Auto-generated catch block with all exceptions
               e.printStackTrace();
           }
           return hmac;
       }
       
       
       @SuppressWarnings("CallToPrintStackTrace")
       SecretKey symKey(String alg, String src){
           SecureRandom random = new SecureRandom();
           byte[] key_data = new byte[16];
           random.nextBytes(key_data);
           //SecretKeySpec sks = new SecretKeySpec(key_data, alg);
           SecretKeyFactory factory;
           SecretKey secretKey = null;
           String passwd = new String();
           if(src.equalsIgnoreCase("server")){
                  passwd = Base64.getEncoder().encodeToString(Client.server_public_key.getEncoded());
           }
           if(src.equalsIgnoreCase("client")){
                  passwd = Base64.getEncoder().encodeToString(Client.client_public_key.getEncoded());
           }
           char[] passwd_array = passwd.toCharArray();
           try{
               factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
               KeySpec spec = new PBEKeySpec(passwd_array, key_data, 65536, 256);
               SecretKey tmp_key = factory.generateSecret(spec);
               secretKey = new SecretKeySpec(tmp_key.getEncoded(), alg);
           }catch(NoSuchAlgorithmException | InvalidKeySpecException e){
               //Auto-generated catch block with all exceptions;
               e.printStackTrace();
           }
           return secretKey;
       }
       
       @SuppressWarnings({"CallToPrintStackTrace", "null"})
       PublicKey createKeys(String alg, String dst){
           KeyPairGenerator kpg;
           KeyPair key_pair = null;
           try{
               kpg = KeyPairGenerator.getInstance(alg);
               kpg.initialize(1024);
               key_pair = kpg.generateKeyPair();
               if(dst.equals("server")){
                   Client.server_private_key = key_pair.getPrivate();
               }
               else if(dst.equals("client")){
                   Client.client_private_key = key_pair.getPrivate();
               }
           }catch(NoSuchAlgorithmException e){
               //Auto-generated catch block with all exceptions;
               e.printStackTrace();
           }
           return key_pair.getPublic();
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       boolean validateSignature(X509Certificate cert, String str, byte[] sign){
           try{
               Signature signature = Signature.getInstance("SHA1withRSA");
               PublicKey pub_key = cert.getPublicKey();
               signature.initVerify(pub_key);
               signature.update(str.getBytes(StandardCharsets.UTF_8));
               return signature.verify(sign);
           }catch(InvalidKeyException | SignatureException | NoSuchAlgorithmException e){
               //Auto generated catch block with alll exceptions;
               e.printStackTrace();
           }
           return false;
       }
       
       @SuppressWarnings({"CallToPrintStackTrace", "null", "UnusedAssignment", "Convert2Diamond"})
       boolean validateCertificate(X509Certificate cert) throws CertificateNotYetValidException{
           FileInputStream input = null;
           Set<X509Certificate> cert_set;
           cert_set = new HashSet<X509Certificate>();
           KeyStore key_store = null;
           
           File f = new File("/opt/bar/cfg/CC_KS");
           try{
               input = new FileInputStream(f);
               key_store = KeyStore.getInstance(KeyStore.getDefaultType());
               String password = "password";
               key_store.load(input, password.toCharArray());
               
               Enumeration Enum = key_store.aliases();
               while(Enum.hasMoreElements()){
                   String alias = (String)Enum.nextElement();
                   System.out.println("ALIAS: " + alias);
                   cert_set.add((X509Certificate) key_store.getCertificate(alias));
               }
               System.out.println("End of ALIAS!");
           }catch(NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e1){
               //Auto generated catch block with all exceptions;
               e1.printStackTrace();
           }
           
           TrustAnchor trust_anchor = null;
           try{
               boolean flag1 = false;
               boolean flag2 = true;
               List my_lst = new ArrayList();
               CertPath path = null;
               CertificateFactory factory = CertificateFactory.getInstance("X.509");
               X509Certificate tmp_cert = null;
               System.out.println("Searching certificates...");
               while(flag2){
                   for(X509Certificate certs : cert_set){
                       //System.out.println("Searching certificate list");
                       if(cert.getIssuerDN().toString().equals(certs.getSubjectDN().toString())){
                           System.out.println("--------------------------MIDTERM CERTIFICATE-----------------------------");
                           System.out.println("Certificate: " + cert.toString());
                           System.out.println("--------------------------------------------------------------------------");
                           tmp_cert = certs;
                           flag1 = true;
                           try{
                               cert.checkValidity();
                               my_lst.add(certs);
                               System.out.println("VALID CERTIFICATE!!!");
                           }catch(CertificateNotYetValidException | CertificateExpiredException e){
                               System.err.println("ERROR! EXPIRED CERTIFICATE!!!");
                           }
                       }
                   }
                   if(flag1 == true){
                       cert = tmp_cert;
                   }
                   System.out.println("Checking for root certificate...");
                   if(tmp_cert.getSubjectDN().toString().equals(tmp_cert.getIssuerDN().toString())){
                       flag2 = false;
                       trust_anchor = new TrustAnchor(cert, null);
                       System.out.println("-------------------------ROOT CERTIFICATE------------------------------");
                       System.out.println("Certificate: " + cert.toString());
                       System.out.println("-----------------------------------------------------------------------");

                   }
               }
               path = factory.generateCertPath(my_lst);
               PKIXParameters params = new PKIXParameters(Collections.singleton(trust_anchor));
               params.setRevocationEnabled(false);
               CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
               PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(path, params);
               if(result != null){
                   System.out.println("End of certificate validation!");
                   return true;
               }
           }catch(NoSuchAlgorithmException | CertificateException | InvalidAlgorithmParameterException | CertPathValidatorException e2){
               //Auto generated catch block with all exceptions
               e2.printStackTrace();
           }
           System.out.println("END OF CERTIFICATE VALIDATION!");
           return false;
       }
       
    @Override
    public void run() {
        //printMenu();
        while (true) {
            if(process_msg == false){
                printMenu();
                System.out.println("Inserting command...");
                insertCommand(command);
            }
            System.out.println("Reading command...");
            JsonObject cmd = readCommand();
            System.out.println("Checking if null...");
            if (cmd == null) {
                try {
                    client_socket.close();
                } catch (Exception e) {}
                return;
            }
            System.out.println("Executing command...");
            executeCommand(command, cmd);
        }
        
    }
    
    
}
