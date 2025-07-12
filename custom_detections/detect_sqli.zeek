module SQLi;

export {
  redef enum Notice::Type += { SQLi_Detected };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
  print fmt("DEBUG - original_URI: %s", original_URI);

  if ( /or\s*1\s*=\s*1/i in original_URI )
  {
    NOTICE([$note=SQLi_Detected,
            $msg=fmt("Possible SQLi detected: %s", original_URI),
            $conn=c]);
  }
}
