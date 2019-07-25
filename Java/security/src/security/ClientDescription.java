/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.io.OutputStream;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;


import com.google.gson.*;

/**
 *
 * @author pedro
 */
class ClientDescription implements Comparable {
    String id;               //id extracted from the JASON description;
    JsonElement description; //JSON description of the client, including the id;
    OutputStream out;        //Stream to send messages to the client;
    PublicKey client_public_key = null;
    PrivateKey server_private_key = null;
    SecretKey session_secret_key = null;
    int phase_int = 0;
    X509Certificate pub_cert = null;
    boolean signed = false;
    
    ClientDescription(String id, JsonElement description, OutputStream out){
        this.id = id;
        this.description = description;
        this.out = out;
    }
    
    @Override
    public int compareTo(Object x){
        return ((ClientDescription) x).id.compareTo(id);
    }
    
}
