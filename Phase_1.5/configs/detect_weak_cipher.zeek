module SSL_Fortify;

export {
    redef enum Notice::Type += {
        SSL_Fortify::Weak_Cipher
    };
}

event ssl_established(c: connection) {
    if ( c$ssl$cipher == "TLS_RSA_WITH_AES_256_CBC_SHA" ) {
        local msg = fmt("⚠️ Weak cipher detected: %s | %s -> %s",
                        c$ssl$cipher, c$id$orig_h, c$id$resp_h);
        NOTICE([$note=SSL_Fortify::Weak_Cipher,
                $msg=msg,
                $conn=c]);
        print msg;
    }
}

