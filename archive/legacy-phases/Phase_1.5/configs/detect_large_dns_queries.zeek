@load base/protocols/dns

module DNS_Fortify;

export {
    redef enum Notice::Type += { Suspicious_DNS_Query };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
    {
    if ( |query| > 63 || qtype == 16 || qtype == 255 )
        {
        NOTICE([$note=Suspicious_DNS_Query,
                $msg=fmt("Suspicious DNS query: %s with qtype %s", query, qtype),
                $conn=c]);
        }
    }
