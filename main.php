<?php

class RC4
{
    public static function calc(string $data, string $key) : string
    {
        $s = [];
        for($i = 0; $i < 256; $i++)
        {
            $s[$i] = $i;
        }

        $j = 0;
        for($i = 0; $i < 256; $i++)
        {
            $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
            list($s[$i], $s[$j]) = [$s[$j], $s[$i]];
        }

        $i = $j = 0;
        $ret = '';
        for($k = 0; $k < strlen($data); $k++)
        {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            list($s[$i], $s[$j]) = [$s[$j], $s[$i]];
            $ret .= $data[$k] ^ chr($s[($s[$i] + $s[$j]) % 256]);
        }

        return $ret;
    }
}

if($argc < 2)
{
    echo '[!] Error: Invalid argument' . PHP_EOL;
    exit(-1);
}

// check tshark
$is_windows = strpos(PHP_OS, 'WIN') !== false;
$command = ($is_windows ? 'where' : 'which') . ' tshark';
exec($command, $output, $ret);
$exist_tshark = false;
if(count($output) > 0)
{
    if($is_windows)
    {
        $exist_tshark = strpos($output[0], 'tshark') !== false;
    }
    else
    {
        $exist_tshark = !(strpos($output[0], 'which: no tshark in') !== false);
    }
}
if(!$exist_tshark)
{
    echo '[!] Error: Please install tshark & set PATH' . PHP_EOL;
    exit(-1);
}

// if arg is URL => download
$pcap = $argv[1];
if(preg_match('/^https?:\/\//', $argv[1]))
{
    $pcap = date('Y-m-d_H-i-s') . '.pcap';
    file_put_contents($pcap, file_get_contents($argv[1]));
}

// create filter
$ip_list =
[
    '37.140.0.0/16',
    '46.109.0.0/16',
    '46.165.0.0/16',
    '46.173.0.0/16',
    '87.106.0.0/16',
    '89.185.0.0/16',
    '93.189.0.0/16',
    '146.255.0.0/16',
    '185.159.0.0/16',
    '194.58.0.0/16',
    '194.87.0.0/16',
    '195.38.0.0/16',
    '195.133.0.0/16',
    '208.100.0.0/16',
    '217.20.0.0/16'
];
for($i=0; $i<count($ip_list); $i++)
{
    $ip_list[$i] = 'ip.addr == ' . $ip_list[$i];
}
$ip_list = implode(' or ', $ip_list);
$filter = 'tcp.port == 443 && (' . $ip_list . ')';

// parse by tshark => json
ob_start();
passthru('tshark -r ' . $pcap . ' -Y "' . $filter . '" -l -n -T json');
$json = ob_get_contents();
ob_end_clean();
$json = json_decode($json, true);

// parse payload
$payload = '';
for($i=0; $i<count($json); $i++)
{
    if(isset($json[$i]['_source']['layers']['tcp']['tcp.payload']))
    {
        $payload .= $json[$i]['_source']['layers']['tcp']['tcp.payload'];
    }
}
$data = str_replace(':', '', $payload);
$output = '';
for($i=0; $i<strlen($data); $i+=2)
{
    $output .= $data[$i] . $data[$i+1] . ':';
}
$data = explode(':', $output);

// 00 ff            magic number
// 01 23 45 67      length
// 21               command
// 00               chunk magic
// 01 23 45 67 89   data
// Ref: https://www.cert.pl/news/single/ramnit-doglebna-analiza/
$magic_header = ['00', 'ff'];
$chunk_header = ['00', '01', '02'];
$codes = [];
for($i=0; $i<count($data); $i++)
{
    // check magic
    if($data[$i] === $magic_header[0] && $data[$i+1] === $magic_header[1])
    {
        // get length
        $packet_length = $data[$i+5] . $data[$i+4] . $data[$i+3] . $data[$i+2];
        $packet_length = hexdec($packet_length);

        // get command
        $command = $data[$i+6];

        // get chunk magic
        $chunk_magic = $data[$i+7];
        if(in_array($chunk_magic, $chunk_header))
        {
            $command_data = array_slice($data, $i+7, $packet_length-1);
            $command_data = implode(':', $command_data);
            $codes[] =
            [
                'command' => $command,
                'data'    => $command_data
            ];
            $i += $packet_length;
        }
    }
}
// file_put_contents('code.json', json_encode($codes));

// parse chunk
$data = [];
foreach($codes as $code)
{
    $command = $code['command'];
    $binary_data = explode(':', $code['data']);
    for($i=0; $i<count($binary_data); $i++)
    {
        $chunk_magic = $binary_data[$i];
        $binary_length = count($binary_data);
        if($chunk_magic === '00' && $binary_length >= $i+5)
        {
            // get length
            $length = $binary_data[$i+4] . $binary_data[$i+3] . $binary_data[$i+2] . $binary_data[$i+1];
            $length = hexdec($length);
            $rc4_data = array_slice($binary_data, $i+5, $length);
            $rc4_string = [];
            for($j=0; $j<count($rc4_data); $j++)
            {
                $rc4_string[] = chr(hexdec($rc4_data[$j]));
            }
            $rc4_string = implode('', $rc4_string);
            $rc4_data = RC4::calc($rc4_string, 'fenquyidh');
            $data[] =
            [
                'command'   =>  $command,
                'data'      =>  $rc4_data
            ];
            $i += 4 + $length;
        }
        else if($chunk_magic === '01' && $binary_length >= $i+6)
        {
            $data[] =
            [
                'command'   =>  $command,
                'data'      =>  '0x' . $binary_data[$i+5] . $binary_data[$i+4] . $binary_data[$i+3] . $binary_data[$i+2]
            ];
            $i += 4;
        }
        else if($chunk_magic === '02' && $binary_length >= $i+10)
        {
            $data[] =
            [
                'command'   =>  $command,
                'data'      =>  '0x' . $binary_data[$i+5] . $binary_data[$i+4] . $binary_data[$i+3] . $binary_data[$i+2]
            ];
            $data[] =
            [
                'command'   =>  $command,
                'data'      =>  '0x' . $binary_data[$i+9] . $binary_data[$i+8] . $binary_data[$i+7] . $binary_data[$i+6]
            ];
            $i += 8;
        }
    }
}

$output_dir = '';
$ext = explode('.', $pcap);
$ext = end($ext);
$basename = basename($pcap);
if($basename === $ext)
{
    $output_dir = '_output';
}
else
{
    $output_dir = substr($basename, 0, strlen($basename) - strlen($ext) - 1);
}
if(!file_exists($output_dir))
{
    mkdir($output_dir);
}
$digit = strlen(count($data));
for($i=0; $i<count($data); $i++)
{
    $filename = $output_dir . '/' . str_pad($i, $digit, '0', STR_PAD_LEFT) . '_' . $data[$i]['command'] . '.bin';
    $command = 'Unknown';
    if($data[$i]['command'] === '01')
    {
        $command = 'COMMAND_OK';
    }
    else if($data[$i]['command'] === '11')
    {
        $command = 'GET_DNSCHANGER';
    }
    else if($data[$i]['command'] === '13')
    {
        $command = 'GET_INJECTS';
    }
    else if($data[$i]['command'] === '15')
    {
        $command = 'UPLOAD_COOKIES';
    }
    else if($data[$i]['command'] === '21')
    {
        $command = 'GET_MODULE';
    }
    else if($data[$i]['command'] === '23')
    {
        $command = 'GET_MODULE_LIST';
    }
    else if($data[$i]['command'] === '51')
    {
        $command = 'VERIFY_HOST';
    }
    else if($data[$i]['command'] === 'e2')
    {
        $command = 'REGISTER_BOT';
    }
    else if($data[$i]['command'] === 'e8')
    {
        $command = 'UPLOAD_INFO_GET_COMMANDS';
    }
    echo '[+] ' . $command . '(0x' . $data[$i]['command'] . ')' .
         str_repeat(' ', 25 - strlen($command)) . ' : ' .
         $filename . PHP_EOL;
    file_put_contents($filename, $data[$i]['data']);
}
