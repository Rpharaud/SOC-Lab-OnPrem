module BruteForce;

export {
  redef enum Notice::Type += { Brute_Force_Login };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
  if ( method == "POST" && /login/i in original_URI )
  {
    NOTICE([$note=Brute_Force_Login,
            $msg=fmt("Possible brute force login attempt: %s %s -> %s", method, original_URI, c$id$resp_h),
            $conn=c]);
  }
}
