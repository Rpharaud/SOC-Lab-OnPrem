module Beacon_Fortify;

export {
    redef enum Notice::Type += {
        Beacon_Fortify::Beaconing_Detected
    };
}

global icmp_times: table[addr] of vector of time = table();

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
    if ( c$id$orig_h !in icmp_times )
        icmp_times[c$id$orig_h] = vector();
    icmp_times[c$id$orig_h] += network_time();
}

event check_beaconing() {
    for (ip in icmp_times) {
        local times = icmp_times[ip];
        if ( |times| < 2 )
            next;

        local gap = times[|times|-1] - times[0];
        if ( gap < 30secs ) {
            NOTICE([$note=Beacon_Fortify::Beaconing_Detected,
                    $msg=fmt("Possible beaconing: %s with %d ICMPs in %.2f secs",
                             ip, |times|, gap),
                    $sub=fmt("%s", ip)]);
            print fmt("Possible beaconing: %s with %d ICMPs in %.2f secs",
                      ip, |times|, gap);
        }
    }
    icmp_times = table();
    schedule 10secs { check_beaconing() };
}

event zeek_init() {
    schedule 10secs { check_beaconing() };
}
