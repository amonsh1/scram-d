module server;

import std.random;
import deimos.openssl.rand;
import deimos.openssl.err;

import std.digest.sha;
import std.traits;
import std.array;
import std.digest.hmac;
import std.base64;
import std.format;
import std.string;
import std.uuid;
import std.range;
import std.algorithm.iteration;
import core.exception;

import utils;



class ScramServerException : ScramException{
    this(string msg){super(msg);}
}


struct Client(T)
if(is(T == SHA256) || is(T == SHA1)){

    string salt;
    string stored_key;
    string server_key;
    int iterations;

    string user;
    string nonce;
    string server_nonce;

    string auth_message;

    this(string salt, string stored_key, string server_key, int iterations){
        this.salt = salt;
        this.stored_key = stored_key;
        this.server_key = server_key;
        this.iterations = iterations;
    }

	string getServerFinal(){
        return format!"v=%s"(
            Base64.encode(
                HMAC!T(this.server_key.representation)
                .put(this.auth_message.representation)
                .finish()
            )
        );
    }

	void setClientFinal(string client_final){
        if (this.auth_message is null)
            throw new ScramServerException("First get the first server message 
                                            using the \"getServerFirst\" 
                                            function");
        string[string] d;
        foreach (part; client_final.split(",").filter!((x) => x.length > 1)){
            d[part[0..1]] = part[2..$];
        }
        string r;
        string proof;
        try{	
            r = d["r"];
            proof = d["p"];
        }
        catch (RangeError exc){
            throw new ScramException("Invalid message format");
        }

        if(!r.endsWith(this.server_nonce)){
            new ScramException("Server nonce doesn't match.");
        }
        auto client_signature = HMAC!T(this.stored_key.representation).put(this.auth_message.representation)
                                                                      .finish();

        auto client_key = zip(
            client_signature.dup, Base64.decode(proof)
        ).map!(x => cast(ubyte)(x[0] ^ x[1])).array;

        if(digest!SHA1(client_key) != this.stored_key.representation){
            new ScramException("The client keys don't match.");
        }
    }
    string getServerFirst(){
        if (this.user is null || this.nonce is null || this.server_nonce is null)
            throw new ScramException(
				"\"user\", \"nonce\" and \"server_nonce\" params shoul be set.
				 Do not create the structure \"client\" directly. 
				 Use \"setClientFirst\" from the \"ScramServer\" object"
        );
        auto user_salt = Base64.encode(this.salt.representation);
        this.auth_message = format!"n=%s,r=%s,r=%s%s,s=%s,i=%s,c=%s,r=%s%s"(
            this.user,  this.nonce,      this.nonce, this.server_nonce, 
            user_salt,  this.iterations, Base64.encode("n,,".representation), 
            this.nonce, server_nonce
		);

        return format!"r=%s%s,s=%s,i=%s"(
            nonce, this.server_nonce, user_salt, iterations
        );
    }
}


class ScramServer(T)
if(is(T == SHA256) || is(T == SHA1)){
    Client!T[string] users;

    string server_nonce;
    this(string server_nonce = null){
        this.server_nonce = (server_nonce !is null)? 
                             server_nonce : randomUUID().toString;
    }

    Client!T setClientFirst(string message){
        string[string] d;
        foreach (part; message.split(",").filter!((x) => x.length > 1)){
            d[part[0..1]] = part[2..$];
        }

        try{
            auto client = this.users[d["n"]];
            client.user = d["n"];
            client.nonce = d["r"];
            client.server_nonce = this.server_nonce;
            return client;
        }
        catch (RangeError exc){
            throw new ScramException("Invalid message format");
        }
    }
    void addUser(
        string username, 
        string password, 
        string salt = null, 
        int iterations = 4096
    ){
        if(salt is null){
            auto buffer = new ubyte[](16);
            RAND_pseudo_bytes(buffer.ptr, 16);
            salt = cast(string)buffer;
        }
        auto salted_password = make_salted_password!T(
            password, salt, iterations
        );

        auto client_key = HMAC!T(salted_password)
                          .put("Client Key".representation)
                          .finish();

        auto sh = new T();
        sh.put(client_key);
        auto stored_key = sh.finish;

        auto server_key = HMAC!T(salted_password)
                          .put("Server Key".representation)
                          .finish();
        auto u = Client!T(
            salt, 
            cast(string)stored_key.dup, 
            cast(string)server_key.dup, 
            iterations
        );
        this.users[username] = u;
    }
}
