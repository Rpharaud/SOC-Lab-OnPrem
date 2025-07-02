# ============================
# detect_weak_ssh_keys.zeek
# Fortify SSH handshake inspection
# ============================

@load base/protocols/ssh

module SSH_Fortify;

export {
    redef enum Notice::Type += {
        Weak_SSH_Key,
        Weak_SSH_Cipher
    };
}

event SSH::log_ssh(rec: SSH::Info) 
{
    # Debug: log each SSH handshake seen
    print fmt("SSH Session: %s:%s -> %s:%s | Host Key Alg: %s | Cipher: %s",
          rec$id$orig_h, rec$id$orig_p,
          rec$id$resp_h, rec$id$resp_p,
          rec$host_key_alg, rec$cipher_alg);


    # Condition 1: Flag RSA keys (simplified, pattern match)
    if ( /ssh-rsa/ in rec$host_key_alg ) {
        NOTICE([$note=Weak_SSH_Key,
                $msg=fmt("Weak SSH host key algorithm used: %s", rec$host_key_alg),
                $src=rec$id$orig_h,
		$dst=rec$id$resp_h]);
    }

    # Condition 2: Flag known weak cipher if used
    if ( rec$cipher_alg == "aes128-cbc" || rec$cipher_alg == "3des-cbc" ) {
        NOTICE([$note=Weak_SSH_Cipher,
                $msg=fmt("Weak SSH cipher negotiated: %s", rec$cipher_alg),
                $src=rec$id$orig_h,
		$dst=rec$id$resp_h]);
    }
}
