module client;

import std.stdio;
import std.exception;
import std.base64;
import std.digest.sha;
import std.digest.hmac;
import std.uuid;
import std.format;
import std.string;
import std.conv;

import utils;


class ScramClientException : ScramException{
    this(string msg){super(msg);}
}


class ScramClient(T)
if(is(T == SHA256) || is(T == SHA1)){

    string name;
	string password;
    string client_nonse;

    string server_nonce;
    string salt;
    int iterations;
    string auth_message;
    string server_signature;

    this(string name, string password, string client_nonse = null){
        enforce(name !is null, "name cannot be null");
        enforce(password !is null, "password cannot be null");
        this.name = name;
        this.password = password;
        this.client_nonse = (client_nonse !is null)? client_nonse : randomUUID().toString;

    }
    string getFirstClient(){
        return format!("n,,n=%s,r=%s")(this.name, this.client_nonse);
    }
    void setFirstServer(string server_first){
        foreach (chunk; server_first.split(",")){
            switch(chunk[0]){
                case 'r':{
                    this.server_nonce = chunk[2..$];
                }break;
                case 's':{
                    this.salt = chunk[2..$];
                }break;
                case 'i':{
                    try{
                        this.iterations = chunk[2..$].to!int;
                    }catch(ConvException exc){
                        throw new ScramClientException(
                            format!("\"r=%s\"The number of iterations not number")(chunk)
                        );    
                    }
                }break;
                default:
                    throw new ScramClientException(
                        format!("\"%s\" - Unknown part of message")(chunk)
                    );
            }
        }
        enforce(this.server_nonce.startsWith(this.client_nonse), "The keys don't match");
        this.auth_message = "n="~name~",r="~ this.client_nonse ~ "," ~ server_first ~ ",c=biws," ~ "r=" ~ server_nonce;
    }
    string getFinal(){
        auto enc_salt = Base64.decode(this.salt);
        auto salted_password = make_salted_password!(T)(
            this.password, cast(string)enc_salt, this.iterations
        );
        auto client_key = HMAC!T(salted_password).put("Client Key".representation).finish();
        auto stored_key = digest!T(client_key);
        auto server_key = HMAC!T(salted_password).put("Server Key".representation).finish();
        auto client_signature = HMAC!T(stored_key).put(auth_message.representation).finish();


        ubyte[client_key.length] client_proof;
        for (int i = 0; i < client_key.length; i+=1){
            client_proof[i] = client_key[i] ^ client_signature[i];
        }

        this.server_signature = Base64.encode(
            HMAC!T(server_key).put(auth_message.representation).finish()
        );

        return format!("c=%s,r=%s,p=%s")(
            Base64.encode("n,,".representation), server_nonce, Base64.encode(client_proof)
        );
    }
    void setServerFinal(string server_final){
        enforce(server_final.startsWith("v="), "Invalid message");
        enforce(server_final[2..$] == this.server_signature, "The server signature doesn't match.");
        
    }
}
