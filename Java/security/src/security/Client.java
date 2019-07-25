/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.net.Socket;
import java.net.InetAddress;
import java.security.PublicKey;
import java.security.PrivateKey;

import javax.crypto.SecretKey;

/**
 *
 * @author pedro
 */
public class Client {
    static String client_id = null;
    static String client_name = null;
    
    static PrivateKey client_private_key = null;
    static PrivateKey server_private_key = null;
    static PublicKey client_public_key = null;
    static PublicKey server_public_key = null;
    static SecretKey client_sym_key = null;
    static SecretKey server_sym_key = null;
    
    static boolean client_connected = false;
    static String connected_client_id;
    static String host = null;
    static int port = 0;
    static String sign_prompt = null;
    
    public static void main(String[] args){
        if (args.length < 1) {
            System.err.print( "Usage: port\n" );
            System.exit( 1 );
        }

        host = "localhost";
        port = Integer.parseInt(args[0]);

        try {
            InetAddress address = InetAddress.getByName(host);
            Socket s = new Socket(address, port);
            System.out.print( "Started client on port " + port + "\n" );
            waitForResponse(s);
            
        } catch (Exception e) {
            System.err.print( "Cannot open socket: " + e );
            System.exit( 1 );
        }

    }
    public static void waitForResponse(Socket s){
        ServerControl registry = new ServerControl();

        try {
             ClientActions handler = new ClientActions(s, registry );
             new Thread( handler ).start ();
        } catch ( Exception e ) {
            System.err.print( "Cannot use socket: " + e );
        }
    }
    
}
