/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;

import com.google.gson.*;

/**
 *
 * @author pedro
 */
class UserDescription implements Comparable{
    int id;		             // id extracted from the CREATE command
    JsonElement description;     // JSON user's description
    String uuid;		     // User unique identifier (across sessions)
    String name;                    //User unique name
    OutputStream output;        //outputstream to send messages to the client;
    PrivateKey server_private_key;
    PublicKey client_public_key;
    SecretKey session_secret_key;
    int phase_int = 0;
    X509Certificate pub_cert = null;
    boolean signed = false;

    @SuppressWarnings("UnnecessaryBoxing")
    UserDescription ( int id, JsonElement description ) {
        this.id = id;
        this.description = description;
        uuid = description.getAsJsonObject().get( "uuid" ).getAsString();
        this.output = new ByteArrayOutputStream(1024);
        this.name = new String();
        this.server_private_key = null;
        this.client_public_key = null;
        this.session_secret_key = null;
        description.getAsJsonObject().addProperty( "id", new Integer( id ) );
    }

    UserDescription ( int id ) {
        this.client_public_key = null;
        this.id = id;
    }

    @Override
    public int compareTo ( Object x ) {
        return ((UserDescription) x).id - id;
    }    
}
