module ReverseShell_Fortify;

export {
    redef enum Notice::Type += {
        ReverseShell_Fortify::Suspicious_Non_TLS_443
    };
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 443/tcp )
    {
        # Correct cast: always produces a string
        local svc = ( c?$service ) ? fmt("%s", c$service) : "" ;

        if ( svc == "" )
        {
            local msg = fmt("⚠️ Suspicious plain TCP on port 443: %s -> %s",
                            c$id$orig_h, c$id$resp_h);

            NOTICE([$note=ReverseShell_Fortify::Suspicious_Non_TLS_443,
                    $msg=msg,
                    $conn=c]);

            print msg;
        }
    }
}
