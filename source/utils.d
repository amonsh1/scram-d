module utils;

import std.digest.sha;
import std.digest.hmac;
import std.string;


class ScramException : Exception{
	this(string msg){super(msg);}
}


auto make_salted_password(T)(string password, string salt, int iters)
if(is(T == SHA256) || is(T == SHA1)){
	auto hmac = HMAC!T(password.representation);
	auto ui = hmac.put(salt.representation ~ cast(ubyte[])[0, 0, 0, 1]).finish();
	auto u = ui;
	
	for (int i = 0; i < iters - 1; i += 1){
		ui = HMAC!T(password.representation).put(ui).finish();
		
		for (int index; index < u.length; index +=1){
			u[index] = u[index] ^ ui[index];
		}
	}
	return u;
}
