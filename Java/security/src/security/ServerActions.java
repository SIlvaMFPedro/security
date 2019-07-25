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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.Base64;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.util.HashMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 *
 * @author pedro
 */
class ServerActions implements Runnable{
       boolean registered = false;
       UserDescription user;
       
       Socket client_socket;
       JsonReader in;
       OutputStream out;
       ServerControl registry;
       SecretKey secret_key;
       byte[] iv_user = null;
       HashMap<String, String> banned_users = new HashMap<>();

       ServerActions ( Socket c, ServerControl r ) {
           client_socket = c;
           registry = r;

           try {
               in = new JsonReader( new InputStreamReader ( c.getInputStream(), "UTF-8") );
               out = c.getOutputStream();
           } catch (Exception e) {
               System.err.print( "Cannot use client socket: " + e );
               Thread.currentThread().interrupt();
           }
       }

       JsonObject readCommand () {
           try {
               JsonElement data = new JsonParser().parse( in );
               if (data.isJsonObject()) {
                   return data.getAsJsonObject();
               }
               System.err.print ( "Error while reading command from socket (not a JSON object), connection will be shutdown\n" );
               return null;
           } catch (JsonIOException | JsonSyntaxException e) {
               System.err.print ( "Error while reading JSON command from socket, connection will be shutdown\n" );
               return null;
           }

       }

       void sendResult ( String result, String error ) {
           String msg = "{";

           // Usefull result

           if (result != null) {
               msg += result;
           }

           // error message

           if (error != null) {
               msg += "\"error\":" + error;
           }

           msg += "}\n";

           try {
               System.out.print( "Send result: " + msg );
               out.write ( msg.getBytes( StandardCharsets.UTF_8 ) );
           } catch (Exception e ) {}
       }
        
       void sendResultStream(String type, String result, String error){
           String msg = "{\"type\":\"" + type + "\"";

           // Usefull result

           if (result != null) {
               msg += result;
           }

           // error message

           if (error != null) {
               msg += "\"error\":" + error;
           }

           msg += "}\n";

           try {
               System.out.print( "Send result: " + msg );
               out.write ( msg.getBytes( StandardCharsets.UTF_8 ) );
           } catch (Exception e ) {}
       }

       @SuppressWarnings("CallToPrintStackTrace")
       void executeCommand ( JsonObject data ) {
           JsonElement cmd = data.get( "type" );
           //UserDescription me;

           if (cmd == null) {
               System.err.println ( "Invalid command in request: " + data );
               return;
           }

           // CREATE

           if (cmd.getAsString().equals( "create" )) {
               JsonElement uuid = data.get( "uuid" );

               if (uuid == null) {
                   System.err.print ( "No \"uuid\" field in \"create\" request: " + data );
                   sendResult( null, "wrong request format" );
                   return;
               }

               if (registry.userExists( uuid.getAsString() )) {
                   System.err.println ( "User already exists: " + data );
                   sendResult( null, "uuid already exists" );
                   return;
               }

               data.remove ( "type" );
               user = registry.addUser( data );
               banned_users.put(uuid.getAsString(), "0");
               sendResult( "\"result\":\"" + user.id + "\"", null );
               return;
           }

           // LIST

           if (cmd.getAsString().equals( "list" )) {
               String list;
               int user_lst = 0; // 0 means all users
               JsonElement id = data.get( "id" );

               if (id != null) {
                   user_lst = id.getAsInt();
               }

               System.out.println( "List " + (user_lst == 0 ? "all users" : "user ") + user_lst );

               list = registry.listUsers(user_lst);

               sendResult( "\"data\":" + (list == null ? "[]" : list), null );
               return;
           }

           // NEW

           if (cmd.getAsString().equals( "new" )) {
               JsonElement id = data.get( "id" );
               int user_new = id == null ? -1 : id.getAsInt();

               if (id == null || user_new <= 0) {
                   System.err.print ( "No valid \"id\" field in \"new\" request: " + data );
                   sendResult( null, "wrong request format" );
                   return;
               }

               sendResult( "\"result\":" + registry.userNewMessages( user_new ), null );
               return;
           }
           
           //CONNECT
           if(cmd.getAsString().equals("connect")){
               JsonElement user_id = data.get("uuid");
               JsonElement user_name = data.get("name");
               if(user_id == null){
                   System.err.println("Error! No \\\"uuid\\\" field in \\\"connect\\\" command: \"" + data );
                   sendResult("unknown", null);
                   return;
               }
               if(user_name == null){
                   System.err.println("Error! No \\\"name\\\" field in \\\"connect\\\" command: \"" + data);
                   sendResult("unknown", null);
                   return;
               }
               user.name = user_name.getAsString();
               System.out.println("user name: " + user.name);
               JsonElement phase = data.get("phase");
               if(phase == null){
                   System.err.println("Error! No \\\"phase\\\" field in \\\"connect\\\" command: " + data);
                   sendResult("unknown", null);
                   return;
               }
               if(phase.getAsInt() == 1){
                   System.out.println("Begin phase01");
                   if(registered){
                       System.err.println("Error! The user is already registered in the server: " + data);
                       //send error result;
                       sendResult("connect", "\"phase\"=\"0\", \"data\"=\"error: reconnection\"");
                       return;
                       
                   }
                   if(!registry.userExists(user_id.getAsString())){
                       System.err.println("Error! The user does not exist: " + data);
                       //send error result;
                       sendResult("connect", "\"phase\"=\"0\", \"data\"=\"error: reconnection\"");
                       return;
                   }
                   sendResult("\"type\":\"connect\",\"phase\"=\"2\",\"ciphers\":[\"RSA\",\"AES\"],\"data\"=\"OK\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"", null );
                   System.out.println("End phase01");
                   return;
               }
               else if(phase.getAsInt() == 3){
                   System.out.println("Begin phase03");
                   JsonElement info = data.get("data");
                   //System.out.println(info.getAsString());
                   byte[] byte_array = Base64.getDecoder().decode(info.getAsString());
                   X509EncodedKeySpec key_spec = new X509EncodedKeySpec(byte_array);
                   KeyFactory key_factory;
                   
                   try{
                       key_factory = KeyFactory.getInstance("RSA");
                       String test = key_factory.generatePublic(key_spec).toString();
                       System.out.println(test);
                       user.client_public_key = key_factory.generatePublic(key_spec);
                   }catch(NoSuchAlgorithmException | InvalidKeySpecException e){
                       //Auto-generated catch block with all exceptions;
                       e.printStackTrace();
                   }
                   PublicKey server_public_key = createKeys("RSA");
                   String pub = Base64.getEncoder().encodeToString(server_public_key.getEncoded());
                   String result = "\"type\":\"connect\",\"phase\"=\"4\",\"ciphers\":[\"RSA\",\"AES\"], \"data\"=\"" + pub + "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"";
                   sendResult(result, null);
                   System.out.println("End phase03");
                   return;
               }
               else if(phase.getAsInt() == 5){
                   System.out.println("Begin phase05");
                   JsonElement info = data.get("data");
                   JsonElement cert = data.get("Certificate");
                   JsonElement sign = data.get("Signature");
                   
                   byte[] byte_array1 = Base64.getDecoder().decode(info.getAsString());
                   byte[] decoded_key = decipherMessage("RSA", byte_array1, null, "asym");
                   //we need to rebuild the key using SecretKeySpec;
                   byte[] byte_array2 = Base64.getDecoder().decode(decoded_key);
                   SecretKey original_key = new SecretKeySpec(byte_array2, 0, byte_array2.length, "AES");
                   String str = Base64.getEncoder().encodeToString(original_key.getEncoded());
                   
                   if(!(sign.getAsString().equals("")) && !(cert.getAsString().equals(""))){
                       System.out.println("Certificate: " + cert.toString());
                       X509Certificate x509_cert = null;
                       byte[] src = Base64.getDecoder().decode(cert.getAsString());
                       InputStream bin = new ByteArrayInputStream(src);
                       CertificateFactory cert_factory;
                       
                       try{
                           cert_factory = CertificateFactory.getInstance("X.509");
                           x509_cert = (X509Certificate)cert_factory.generateCertificate(bin);
                           //check if the certificate is valid
                           if(validateCertificate(x509_cert)){
                               user.pub_cert = x509_cert;
                               byte[] tmp = Base64.getDecoder().decode(sign.getAsString());
                               if(validateSignature(x509_cert, str, tmp)){
                                   user.signed = true;
                               }
                               else{
                                   System.err.println("ERROR! Invalid certificate!");
                               }
                           }
                       }catch(CertificateException e){
                           //Auto generated catch block with all exceptions
                           e.printStackTrace();
                       } 
                   }
                   user.session_secret_key = original_key;
                   String result = "OK";
                   secret_key = user.session_secret_key;
                   byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
                   result = "\"type\":\"connect\",\"phase\"=\"6\",\"ciphers\":[\"RSA\",\"AES\"],\"data\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) + "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"";
                   sendResult(result, null);
                   //registered = true;
                   System.out.println("End phase05");
                   return;
               }
               else if(phase.getAsInt() < 1 || phase.getAsInt() > 5){
                   System.err.println("Error! Invalid phase number assigned!");
                   //send error result;
                   sendResult( "connect", "\"phase\"=\"0\", \"data\"=\"error: not implemented\"" );
                   return;
               }
               registered = true;
               return;
           }
           
           //SECURE
           if(cmd.getAsString().equals("secure")){
               String str = null;
               byte[] byte_array = Base64.getDecoder().decode(data.get("payload").getAsString().getBytes(StandardCharsets.UTF_8));
               byte[] iv_array = Base64.getDecoder().decode(data.get("iv").getAsString().getBytes(StandardCharsets.UTF_8));
               byte[] pay_load = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym");
               try{
                   str = new String(pay_load, "UTF8");
               }catch(UnsupportedEncodingException e){
                   //Auto-generated catch block
                   e.printStackTrace();
               }
               JsonElement sign = data.get("Signature");
               JsonObject payload = new JsonParser().parse(str).getAsJsonObject();
               byte[] hmac = getHMAC(str, user.session_secret_key);
               JsonElement sa_data = data.get("sa-data");
               
               //validate the signature;
               if(!(sign.getAsString().equals(""))){
                   X509Certificate x509_cert = user.pub_cert;
                   byte[] sig = Base64.getDecoder().decode(sign.getAsString());
                   System.out.println("Signature: " + Arrays.toString(sig));
                   if(validateSignature(x509_cert, str, sig)){
                       System.out.println("CHECKED! The signature is VALID!");
                       
                   }
               }
               if(!(Base64.getEncoder().encodeToString(hmac).equals(sa_data.getAsString()))){
                   System.err.println("Error! The message has been compromised!");
                   return;
               }
               System.out.println("HMAC: " + sa_data.getAsString());
               JsonElement inner_cmd = (payload == null) ? null : payload.get("type");
               if(inner_cmd == null){
                   System.err.println("Error! Invalid inner comand line assigned!");
                   //send error result;
                   sendResult("secure", "\"payload\"=\"error: type field missing\"");
                   return;
               }
               switch (inner_cmd.getAsString()) {
                   case "client-connect":
                   case "client-disconnect":
                   case "client-com":
                   case "ack":
                       {
                           @SuppressWarnings("null")
                           JsonElement user_id = payload.get("dst");
                           JsonElement user_name = payload.get("name");
                           String result;
                           //check if dst id is valid
                           if(user_id == null || !registry.containsUser(user_id.getAsString())){
                               System.err.println("Error! Invalid dst user id...");
                               //send error result
                               sendResult("secure", "\"payload\"=\"error: dst field missing\"");
                               return;
                           }
                           
                           //check if dst name is valid
                           if(!user_name.getAsString().equals(registry.getUserName(user_id.getAsString()))){
                               System.err.println("Error! Invalid dst name...");
                               //send error result
                               sendResult("secure", "\"payload\"=\"error: name field missing\"");
                               return;
                           }
                           //check if src id is valid
                           if(payload.get("src") == null){
                               System.err.println("Error! Invalid src user id...");
                               //send error result
                               sendResult("secure","\"payload\"=\"error:src field missing\"");
                               return;
                           }
                           //check if src and dst sign their messages
                           if(!registry.signedUser(user_id.getAsString()) || !registry.signedUser(payload.get("src").getAsString())){
                               System.err.println("Error! One of the users does not sign his/her messages...");
                               //send error result
                               sendResult("secure","\"payload\"=\"error: CC missing!\"");
                               return;
                           }
                           //check if src and dst are the same
                           if(payload.get("src") == payload.get("dst")){
                               System.err.println("Error! Stop connecting yourself...");
                               //send error result
                               sendResult("secure","\"payload\"=\"error: src and dst field are the same\"");
                               return;
                           }
                           System.out.println("user ID: " + user_id.getAsString());
                           System.out.println("user name: " + user_name.getAsString());
                           OutputStream target_stream;
                           target_stream = registry.getOutputStream(user_id.getAsString());
                           //check if target stream is valid
                           if(target_stream == null){
                               System.out.println("Checking target stream...");
                               System.err.println("Error! Invalid target stream...");
                               //send error result
                               sendResult( "secure", "\"payload\"=\"error: target dst not found\"" );
                               return;
                           }
                           //CLIENT-CONNECT
                           if(inner_cmd.getAsString().equals("client-connect")){
                               JsonElement phase = payload.get("phase");
                               if(phase == null){
                                    System.err.println("Error! No \\\"phase\\\" field in \\\"client-connect\\\" command: " + data);
                                    sendResult("unknown", null);
                                    return;
                               }
                               if(phase.getAsInt() == 1){
                                    System.out.println("Begin PHASE01");
                                    String src_id = payload.get("src").getAsString();
                                    System.out.println("DST ID: " + user_id.getAsString() + "\nBANNED USER ID: " + banned_users.get(user_id.getAsString()));
                                    if(src_id.equals(banned_users.get(user_id.getAsString()))){
                                        System.err.println("This user has banned you!");
                                        //send error result;
                                        sendResult("secure", "\"dst\"=\"error: Banned connection found!\"");
                                        return;
                                    }
                                    else{
                                        secret_key = registry.getSessionKey(payload.get("src").getAsString());
                                        PublicKey public_key = registry.getUserPK(user_id.getAsString());
                                        String pub_key = Base64.getEncoder().encodeToString(public_key.getEncoded());
                                        result = "{\"type\":\"client-connect\",\"inner-sdata\":\"\",\"dst\"=\"" + payload.get("dst").getAsString() + "\",\"name\"=\"" + payload.get("name").getAsString() + "\",\"src\"=\"" + payload.get("src").getAsString() + "\",\"phase\"=\"2\", \"data\"=\"" + pub_key  + "\"}";
                                        hmac = getHMAC(result, secret_key);
                                        byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
                                        result = "\"type\":\"secure\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"";
                                        sendResult(result, null);
                                    }
                                    System.out.println("End PHASE01");
                               }
                               else if(phase.getAsInt() == 3){
                                    System.out.println("Begin PHASE03");
                                    JsonElement msg_data = payload.get("data");
                                    if(msg_data.getAsString().equals("OK")){
                                        String cmd_msg = "OK";
                                        result = "{\"type\":\"client-connect\",\"inner-sdata\":\"\",\"dst\"=\"" + payload.get("dst").getAsString() + "\",\"name\"=\"" + payload.get("name").getAsString() + "\",\"src\"=\"" + payload.get("src").getAsString() + "\",\"phase\"=\"4\", \"data\"=\"" + cmd_msg + "\"}";
                                        secret_key = registry.getSessionKey(payload.get("src").getAsString());
                                        hmac = getHMAC(result, secret_key);
                                        byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
                                        result = "\"type\":\"secure\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"";
                                        sendResult(result, null);
                                        System.out.println("End PHASE03");    
                                    }
                                    else{
                                        System.err.println("Error! Connection lost!");
                                        sendResult("unknown", null);
                                        return;
                                    } 
                               }
                               else{
                                   System.err.println("Error! Invalid \\\"phase\\\" field in \\\"client-connect\\\" command: " + data);
                                   sendResult("unknown", null);
                                   return;
                               }
                           }
                           //CLIENT-COM
                           else if(inner_cmd.getAsString().equals("client-com")){
                                System.out.println("Begin client communication...");
                                /*
                                byte[] dst_byte = Base64.getDecoder().decode(payload.get("dst").getAsString());
                                byte[] src_byte = Base64.getDecoder().decode(payload.get("src").getAsString());
                                byte[] name_byte = Base64.getDecoder().decode(payload.get("name").getAsString());
                                byte[] msg_sign_byte = Base64.getDecoder().decode(payload.get("inner-msg-sig").getAsString());
                                byte[] msg_hmac_byte = Base64.getDecoder().decode(payload.get("inner-sdata").getAsString());
                                byte[] msg_data_byte = Base64.getDecoder().decode(payload.get("data").getAsString());
                                byte[] iv_byte = Base64.getDecoder().decode(payload.get("iv").getAsString());
                                byte[] key_sign_byte = Base64.getDecoder().decode(payload.get("inner-key-sig").getAsString());
                                byte[] key_send_byte = Base64.getDecoder().decode(payload.get("key_msg").getAsString());
                                byte[] key_rec_byte = Base64.getDecoder().decode(payload.get("key_rec").getAsString());
                                
                                String dst = Base64.getEncoder().encodeToString(dst_byte);
                                String src = Base64.getEncoder().encodeToString(src_byte);
                                String name = Base64.getEncoder().encodeToString(name_byte);
                                String msg_sign = Base64.getEncoder().encodeToString(msg_sign_byte);
                                String msg_hmac = Base64.getEncoder().encodeToString(msg_hmac_byte);
                                String msg_data = Base64.getEncoder().encodeToString(msg_data_byte);
                                String iv = Base64.getEncoder().encodeToString(iv_byte);
                                String key_sign = Base64.getEncoder().encodeToString(key_sign_byte);
                                String key_send = Base64.getEncoder().encodeToString(key_send_byte);
                                String key_rec = Base64.getEncoder().encodeToString(key_rec_byte);
                                */
                                String dst = payload.get("dst").getAsString();
                                String src = payload.get("src").getAsString();
                                String name = payload.get("name").getAsString();
                                String msg_sign = payload.get("inner-msg-sig").getAsString();
                                String msg_hmac = payload.get("inner-sdata").getAsString();
                                String msg_data = payload.get("data").getAsString();
                                String iv = payload.get("iv").getAsString();
                                String key_sign = payload.get("inner-key-sig").getAsString();
                                String key_send = payload.get("key_msg").getAsString();
                                String key_rec = payload.get("key_rec").getAsString();
                                
                                Set<String> setInput_msg = new TreeSet<>();
                                setInput_msg.add("\"DST\":\"" + dst);
                                setInput_msg.add("SRC\":\"" + src + "\"");
                                setInput_msg.add("NAME\":\"" + name);
                                setInput_msg.add("MSG_SIGN\":\"" + msg_sign);
                                setInput_msg.add("MSG_HMAC\":\"" + msg_hmac);
                                setInput_msg.add("MSG_DATA\":\"" + msg_data);
                                setInput_msg.add("IV\":\"" + iv);
                                setInput_msg.add("KEY_SIGN\":\"" + key_sign);
                                setInput_msg.add("KEY\":\"" + key_send);
                                String msg = setInput_msg.stream().collect(Collectors.joining("\",\""));
                                String send_msg = "{" + msg + "}";
                                System.out.println(send_msg);
                                
                                Set<String> setInput_clone = new TreeSet<>();
                                setInput_clone.add("\"DST\":\"" + dst);
                                setInput_clone.add("SRC\":\"" + src + "\"");
                                setInput_clone.add("NAME\":\"" + name);
                                setInput_clone.add("MSG_SIGN\":\"" + msg_sign);
                                setInput_clone.add("MSG_HMAC\":\"" + msg_hmac);
                                setInput_clone.add("MSG_DATA\":\"" + msg_data);
                                setInput_clone.add("IV\":\"" + iv);
                                setInput_clone.add("KEY_SIGN\":\"" + key_sign);
                                setInput_clone.add("KEY\":\"" + key_rec);
                                String clone = setInput_clone.stream().collect(Collectors.joining("\",\""));
                                String clone_msg = "{" + clone + "}";
                                System.out.println(clone_msg);
                                
                                if (src == null || dst == null || msg == null || clone == null) {
                                        System.err.print ( "Badly formated \"send\" request: " + data );
                                        sendResult( null, "wrong request format" );
                                        return;
                                }

                                int srcId = payload.get("src").getAsInt();
                                int dstId = payload.get("dst").getAsInt();
                                
                                System.out.println("SRC_ID: " + srcId);
                                System.out.println("DST_ID: " + dstId);

                                if (registry.userExists( srcId ) == false) {
                                    System.err.print ( "Unknown source id for \"send\" request: " + data );
                                    sendResult( null, "wrong parameters" );
                                    return;
                                }

                                if (registry.userExists( dstId ) == false) {
                                    System.err.print ( "Unknown destination id for \"send\" request: " + data );
                                    sendResult( null, "wrong parameters" );
                                    return;
                                }

                                // Save message and copy
                                String response = registry.sendMessage( srcId, dstId, send_msg, clone_msg);
                                //sendResult( "\"result\":" + response, null );
                                
                                // Send ack
                                String ack = "OK";
                                result = "{\"type\":\"client-com\",\"inner-sdata\":\"\",\"dst\"=\"" + payload.get("dst").getAsString() + "\",\"name\"=\"" + payload.get("name").getAsString() + "\",\"src\"=\"" + payload.get("src").getAsString() + "\",\"data\"=\"" + ack + "\",\"result\":" + response + "\"}";
                                secret_key = registry.getSessionKey(payload.get("src").getAsString());
                                hmac = getHMAC(result, secret_key);
                                byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
                                result = "\"type\":\"secure\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"";
                                sendResult(result, null);
                                System.out.println("End of client communication...");
                                return;
 
                           }
                           //CLIENT-DISCONNECT
                           else if(inner_cmd.getAsString().equals("client-disconnect")){
                                JsonElement disconnect = payload.get("data");
                                if(!disconnect.getAsString().equals("DC")){
                                    System.err.println("Error! Invalid disconnect input message!");
                                    sendResult(null, "wrong parameters");
                                }
                                JsonElement banned_id = payload.get("dst");
                                String banned_user_id = banned_id.getAsString();
                                banned_users.put(payload.get("src").getAsString(), banned_user_id);
                                System.out.println("SRC ID: " + payload.get("src").getAsString() + "\nBANNED USER ID: " + banned_users.get(payload.get("src").getAsString()));
                                String response = "DC";
                                result = "{\"type\":\"client-disconnect\",\"inner-sdata\":\"\",\"dst\"=\"" + payload.get("dst").getAsString() + "\",\"name\"=\"" + payload.get("name").getAsString() + "\",\"src\"=\"" + payload.get("src").getAsString() + "\",\"result\":\"" + response + "\"}";
                                secret_key = registry.getSessionKey(payload.get("src").getAsString());
                                hmac = getHMAC(result, secret_key);
                                byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
                                result = "\"type\":\"secure\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"";
                                sendResult(result, null);
                                System.out.println("A client has been disconnected...");
                           }
                           else{
                               secret_key = user.session_secret_key;
                               result = "{\"type\"=\"" + inner_cmd.getAsString() + "\", \"data\"=" + payload.get("data") + "}";
                               hmac = getHMAC(result, secret_key);
                               byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
                               result = "\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"payload\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + ",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\",\"port\"=\"8080\",\"ip\"=\"127.0.0.1\"}";
                                
                           }
                           //sendResultStream("secure", result, null, target_stream);
                           break;
                       }
                   default:
                       System.err.println("Error! Invalid command type!");
                       //send error result
                       sendResult( "secure", "\"payload\"=\"error: wrong type\"" );
                       return;
               }
               return;
           }

           // ALL

           if (cmd.getAsString().equals( "all" )) {
               JsonElement id = data.get( "id" );
               int user_all = id == null ? -1 : id.getAsInt();

               if (id == null || user_all <= 0) {
                   System.err.print ( "No valid \"id\" field in \"new\" request: " + data );
                   sendResult( null, "wrong request format" );
                   return;
               }

               sendResult( "\"result\":[" + registry.userAllMessages( user_all ) + "," + registry.userSentMessages( user_all ) + "]", null );
               return;
           }
           
           // RECV

           if (cmd.getAsString().equals( "recv" )) {
               JsonElement subdata = data.get("data");
               JsonElement iv = data.get("iv");
               JsonElement uuid = data.get("uuid");
               secret_key = registry.getSessionKey(uuid.getAsString());
               user.session_secret_key = secret_key;
               byte[] byte_array = Base64.getDecoder().decode(subdata.getAsString());
               byte[] iv_array = Base64.getDecoder().decode(iv.getAsString());
               byte[] ack = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym");
               
               String str = new String();
               try{
                   str = new String(ack, "UTF8");
               }catch(UnsupportedEncodingException e){
                   //Auto-generated catch block with all exceptions
                   e.printStackTrace();
               }
               
               JsonObject payload = new JsonParser().parse(str).getAsJsonObject();
               JsonElement id = payload.get( "id" );
               JsonElement msg = payload.get( "msg" );
               JsonElement auth = payload.get( "auth" );
               JsonElement name = payload.get( "authname" );
               
               if (id == null || msg == null || auth == null || name == null) {
                   System.err.print ( "Badly formated \"recv\" request: " + data );
                   sendResult( null, "wrong request format" );
                   return;
               }
               int user_id = 0;
               user_id = id.getAsInt();
               String user_lst = registry.listUsers(user_id);
               @SuppressWarnings("ReplaceStringBufferByString")
               StringBuilder sb = new StringBuilder(user_lst);
               sb.deleteCharAt(0);
               sb.deleteCharAt(sb.length()-1);
               String res = sb.toString();
               System.out.println(res);
               JsonObject obj;
               obj = new JsonParser().parse(res).getAsJsonObject();
               int fromId = obj.get("id").getAsInt(); 
               
               System.out.println("FROM ID: " + fromId);
               
               if (registry.userExists(fromId) == false) {
                   System.err.print ( "Unknown source id for \"recv\" request: " + data );
                   sendResult( null, "wrong parameters" );
                   return;
               }

               if (registry.messageExists( fromId, msg.getAsString() ) == false) {
                   System.err.println ( "Unknown message for \"recv\" request: " + data );
                   sendResult( null, "wrong parameters" );
                   return;
               }
               int user_auth = 0;
               user_auth = auth.getAsInt();
               String auth_lst = registry.listUsers(user_auth);
               sb = new StringBuilder(auth_lst);
               sb.deleteCharAt(0);
               sb.deleteCharAt(sb.length()-1);
               String author = sb.toString();
               System.out.println(author);
               obj = new JsonParser().parse(author).getAsJsonObject();
               String username = registry.getUserName(obj.get("uuid").getAsString());
               
               if (!auth.getAsString().equalsIgnoreCase(obj.get("uuid").getAsString())) {
                   System.err.println ( "Error invalid author id introduced for \"recv\" request: " + data);
                   sendResult( null, "wrong parameters" );
                   return;
               }
               
               if (!name.getAsString().equalsIgnoreCase(username)) {
                   System.err.println ( "Error invalid author name introduced for \"recv\" request: " + data);
                   sendResult( null, "wrong parameters" );
                   return;
               }
               
               String cert = null;
               try{
                    X509Certificate x509_cert = registry.getUserPubCert(auth.getAsString());
                    cert = Base64.getEncoder().encodeToString(x509_cert.getEncoded());
               }catch(CertificateException e){
                    //Auto generated catch block with all exceptions
                    e.printStackTrace();
               }
               
               // Read message

               String response = registry.recvMessage( fromId, msg.getAsString() );
               System.out.println("Received file message: " + response);
               String r = response.replace("[1,", "");
               sb = new StringBuilder(r);
               sb.deleteCharAt(sb.length()-1);
               String file_msg = sb.toString();
               System.out.println("Correct format file message: " + file_msg);
              
               String result = "{\"type\":\"recv\",\"inner-sdata\":\"\",\"dst\":\"" + id.getAsString() + "\",\"result\":" + file_msg + ",\"cert\":\"" + cert + "\"}";
               System.out.println(result);
               byte[] hmac = getHMAC(result, secret_key);
               byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
               result = "\"type\":\"recv\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"data\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\"";
               sendResult(result, null);
               
               return;
           }

           // RECEIPT

           if (cmd.getAsString().equals( "receipt" )) {
               JsonElement subdata = data.get("data");
               JsonElement iv = data.get("iv");
               JsonElement uuid = data.get("uuid");
               System.out.println("UUID: " + uuid.getAsString());
               secret_key = registry.getSessionKey(uuid.getAsString());
               user.session_secret_key = secret_key;
               byte[] byte_array = Base64.getDecoder().decode(subdata.getAsString());
               byte[] iv_array = Base64.getDecoder().decode(iv.getAsString());
               byte[] ack = decipherMessage("AES/CTR/PKCS5Padding", byte_array, iv_array, "sym");
               
               String str = new String();
               try{
                   str = new String(ack, "UTF8");
               }catch(UnsupportedEncodingException e){
                   //Auto-generated catch block with all exceptions
                   e.printStackTrace();
               }
               
               JsonObject payload = new JsonParser().parse(str).getAsJsonObject();
               JsonElement id = payload.get( "id" );
               JsonElement msg = payload.get( "msg" );
               JsonElement receipt = payload.get( "receipt" );

               if (id == null || msg == null || receipt == null) {
                   System.err.print ( "Badly formated \"receipt\" request: " + data );
                   sendResult( null, "wrong request format" );
                   return;
               }
               
               int user_id = 0;
               user_id = id.getAsInt();
               String user_lst = registry.listUsers(user_id);
               @SuppressWarnings("ReplaceStringBufferByString")
               StringBuilder sb = new StringBuilder(user_lst);
               sb.deleteCharAt(0);
               sb.deleteCharAt(sb.length()-1);
               String res = sb.toString();
               System.out.println(res);
               JsonObject obj;
               obj = new JsonParser().parse(res).getAsJsonObject();
               int fromId = obj.get("id").getAsInt(); 
               
               System.out.println("FROM ID: " + fromId);
               
               

               if (registry.messageWasRed( fromId, msg.getAsString() ) == false) {
                   System.err.print ( "Unknown, or not yet red, message for \"receipt\" request: " + data );
                   sendResult( null, "wrong parameters" );
                   return;
               }

               // Store receipt

               registry.storeReceipt( fromId, msg.getAsString(), receipt.getAsString() );
               
               String rec = registry.getReceipts(fromId, msg.getAsString());
              
               String result = "{\"type\":\"receipt\",\"inner-sdata\":\"\",\"dst\":\"" + id.getAsString() + "\"result\":" + rec + "\"msg\":" + msg.getAsString() + "\"}";
               byte[] hmac = getHMAC(result, secret_key);
               byte[] msg_to_send = cipherMessage("AES/CTR/PKCS5Padding", result, secret_key);
               result = "\"type\":\"receipt\",\"sa-data\"=\"" + Base64.getEncoder().encodeToString(hmac) + "\",\"data\"=\"" + Base64.getEncoder().encodeToString(msg_to_send) + "\",\"iv\"=\"" + Base64.getEncoder().encodeToString(iv_user) +  "\"";
               sendResult(result, null);
               
               return;
           }

           // STATUS

           if (cmd.getAsString().equals( "status" )) {
               JsonElement id = data.get( "id" );
               JsonElement msg = data.get( "msg" );

               if (id == null || msg == null) {
                   System.err.print ( "Badly formated \"status\" request: " + data );
                   sendResult( null, "wrong request format" );
                   return;
               }

               int fromId = id.getAsInt();

               if (registry.copyExists( fromId, msg.getAsString() ) == false) {
                   System.err.print ( "Unknown message for \"status\" request: " + data );
                   sendResult( null, "wrong parameters" );
                   return;
               }

               // Get receipts

               String response = registry.getReceipts( fromId, msg.getAsString() );

               sendResult( "\"result\":" + response, null );
               return;
           }
           
           // EXIT
           
           if (cmd.getAsString().equals( "exit" )) {
               JsonElement id = data.get("id");
               user = registry.getUSER(id.getAsString());
               user.server_private_key = null;
               user.session_secret_key = null;
               user.client_public_key = null;
               registered = false;
               
           }

           sendResult( null, "Unknown request" );
       }
       
       @SuppressWarnings({"CallToPrintStackTrace", "null"})
       PublicKey createKeys (String alg){
            KeyPairGenerator kpg;
            KeyPair key_pair = null;
            try {
                    kpg = KeyPairGenerator.getInstance(alg);
                    kpg.initialize(1024);
                    key_pair = kpg.generateKeyPair();
                    user.server_private_key = key_pair.getPrivate();
            } catch (NoSuchAlgorithmException e) {
                    // Auto generated catch block with all exceptions;
                    e.printStackTrace();
            }
            return key_pair.getPublic();
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       byte[] decipherMessage(String alg, byte[] input, byte[] iv, String type){
            byte[] msg = null;
            if(type.equals("asym")){
                    try {
                            Cipher decipher = Cipher.getInstance(alg);
                            decipher.init(Cipher.DECRYPT_MODE, user.server_private_key);
                            msg = decipher.doFinal(input);
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                            //Auto generated catch block with all exceptions;
                            e.printStackTrace();
                    }
            }else if (type.equals("sym")){
                    try {
                            Cipher decipher = Cipher.getInstance(alg);
                            decipher.init(Cipher.DECRYPT_MODE, user.session_secret_key, new IvParameterSpec(iv));
                            msg = decipher.doFinal(input);
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                            //Auto generated catch block with all exceptions;
                            e.printStackTrace();
                    }
            }
            return msg;
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       byte[] cipherMessage (String alg, String input, SecretKey secret_key){
            byte[] msg = null;
            try {
                    Cipher cipher = Cipher.getInstance(alg);
                    cipher.init(Cipher.ENCRYPT_MODE, secret_key);
                    AlgorithmParameters params = cipher.getParameters();
                    iv_user = params.getParameterSpec(IvParameterSpec.class).getIV();
                    msg = cipher.doFinal(input.getBytes("UTF8"));
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidParameterSpecException | UnsupportedEncodingException e) {
                    //Auto generated catch block with all exceptions;
                    e.printStackTrace();
            }
            return msg;
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       byte[] getHMAC(String msg, SecretKey secret_key){
            byte[] hmac = null;
            SecretKeySpec key_spec = new SecretKeySpec(secret_key.getEncoded(),"HmacSHA1");

            try {
                    Mac mac = Mac.getInstance("HmacSHA1");
                    mac.init(key_spec);
                    hmac = mac.doFinal(msg.getBytes());
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    //Auto generated catch block with all exceptions;
                    e.printStackTrace();
            }
            return hmac;
       }
       
       @SuppressWarnings({"CallToPrintStackTrace", "null", "UnusedAssignment", "Convert2Diamond"})
       boolean validateCertificate(X509Certificate cert) throws CertificateNotYetValidException{
           System.out.println("Validating certificate...");
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
               System.out.println("End ALIAS!!!");
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
                       //System.out.println("Searching certificate list...");
                       System.out.println(cert.getIssuerDN());
                       if(cert.getIssuerDN().toString().equals(certs.getSubjectDN().toString())){
                           System.out.println("-------------------------MIDTERM CERTIFICATE------------------------------");
                           System.out.println("Certificate: " + cert.toString());
                           System.out.println("--------------------------------------------------------------------------");
                           tmp_cert = certs;
                           flag1 = true;
                           try{
                               cert.checkValidity();
                               my_lst.add(certs);
                               System.out.println("VALID CERTIFICATE!!!");
                           }catch(CertificateNotYetValidException | CertificateExpiredException e){
                               System.err.println("ERROR! EXPIRED CERTIFICATE" + e);
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
                       System.out.println("-----------------------------ROOT CERTIFICATE-----------------------------");
                       System.out.println("Certificate: " + cert.toString());
                       System.out.println("--------------------------------------------------------------------------");

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
           System.out.println("END OF CERTIFICATE VALIDATION!!");
           return false;
       }
       
       @SuppressWarnings("CallToPrintStackTrace")
       boolean validateSignature(X509Certificate cert, String str, byte[] sign){
           System.out.println("Validating the signature...");
           try{
               Signature signature = Signature.getInstance("SHA1withRSA");
               PublicKey pub_key = cert.getPublicKey();
               signature.initVerify(pub_key);
               signature.update(str.getBytes(StandardCharsets.UTF_8));
               return signature.verify(sign);
           }catch(InvalidKeyException | SignatureException | NoSuchAlgorithmException e){
               //Auto generated catch block with all exceptions
               e.printStackTrace();
           }
           System.out.println("End of signature validation!");
           return false;
       }
       
       @Override
       public void run () {
           while (true) {
               JsonObject cmd = readCommand();
               if (cmd == null) {
                   try {
                       client_socket.close();
                   } catch (Exception e) {}
                   return;
               }
               executeCommand ( cmd );
           }

       }

}
