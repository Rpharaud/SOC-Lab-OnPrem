module HTTP_Fortify;

export {
    redef enum Notice::Type += {
        HTTP_Fortify::Spike_Alert
    };
}

global http_request_counts: table[addr] of count = table();

const spike_threshold = 50; # requests
const spike_interval = 10secs; # window

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if ( c$id$orig_h in http_request_counts )
	http_request_counts[c$id$orig_h] += 1;
    else
	http_request_counts[c$id$orig_h] = 1;
}

event check_spikes() {
    for (ip in http_request_counts) {
        if (http_request_counts[ip] > spike_threshold) {
            local msg = fmt("High HTTP request rate from %s: %d requests in %s",
                            ip, http_request_counts[ip], spike_interval);
            NOTICE([$note=HTTP_Fortify::Spike_Alert,
                    $msg=msg,
                    $sub=fmt("%s", ip)]);
            print msg;
        }
    }
    http_request_counts = table();
    schedule spike_interval { check_spikes() };
}

event zeek_init() {
    schedule spike_interval { check_spikes() };
}
