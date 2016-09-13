<?php

function get_macowners()
{
$file = file('/opt/netflow/oui.txt');
foreach ($file as $value)
    {
        $key = strtolower(substr($value,0,6));
        $massiv_mac[$key] = substr($value,22);
    }
return $massiv_mac;
}

function get_ip_netnames()
{
$db_link = mysqli_connect(DB_HOST, DB_USER, DB_PASS, "netname");
$sql = "SELECT * FROM names;";
$result = mysqli_query($db_link, $sql);
$massiv_ip= array();
while ($row = mysqli_fetch_assoc($result)) {$massiv_ip[] = $row;}
mysqli_free_result($result);
mysqli_close($db_link);

return $massiv_ip;
}

function get_clients($timeout = 0)
{
$clients = array();
$db_link = @mysqli_connect(DB_HOST, DB_USER, DB_PASS, "HOTSPOT");
$sql = "SELECT macaddress, number, UNIX_TIMESTAMP(last_visit) as date, last_ip FROM clients WHERE (UNIX_TIMESTAMP()-".$timeout.")<=UNIX_TIMESTAMP(last_visit);";
$result = @mysqli_query($db_link, $sql);
while ($row = mysqli_fetch_assoc($result)) {$mac = str_replace(":","",$row['macaddress']); $clients[$mac]=array("number"=>$row['number'],"date"=>$row['date'],"ip"=>$row['last_ip']);}
mysqli_free_result($result);
mysqli_close($db_link);

$clients['a0369f51a7dc'] = array("number"=>'70000000000',"date"=>time(),"ip"=>'10.0.0.1');
$clients['a0369f51a7dd'] = array("number"=>'70000000000',"date"=>time(),"ip"=>'10.0.0.1');

return $clients;
}

function send_remote_syslog($message, $ip = false, $port = false) {

  if ($ip == false || $port == false) {$ip=SYSLOG_IP; $port=SYSLOG_PORT;}
  $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
  socket_sendto($sock, $message, strlen($message), 0, $ip, $port);
  socket_close($sock);
}

function log_it($string,$type = false)
{
if(is_array($string)){
    $temp="";
        foreach($string as $key => $value)
        { if(is_array($value)){
            $temp2="";
            foreach ($value as $key2=>$value2){
                $temp2 = $temp2."[".$key2."]=".$value2;}
                $value = $temp2;
            }
        $temp = $temp."[".$key."]=".$value."; ";
        }
    $string=$temp;}
file_put_contents(PATH_LOG,date("d-m-Y H:i:s")."\t".$string."\n",FILE_APPEND);
}

function get_mac_from_arp($ip)
{
    $return = exec("arp -n | grep '".$ip."' | awk {'print $3'}");
    if(strpos($return,":") === false) {return false;} else {return $return;}
}


function get_duration_session($start = false,$stop = false)
{
$date = date_create($start);
$milisec_start = substr($start,strpos($start,".")+1);
$sec_start = date_timestamp_get($date);

$date = date_create($stop);
$milisec_stop = substr($stop,strpos($stop,".")+1);
$sec_stop = date_timestamp_get($date);

$duration_sec = abs($sec_stop - $sec_start);

if ($duration_sec == 0) {$duration_milisec = $milisec_stop - $milisec_start;}
else {$duration_milisec = abs(0-$milisec_stop)+abs(0-$milisec_start);}

$duration = $duration_sec+$duration_milisec/1000;

return $duration;
}


function get_mac_owner($mac)
{
global $massiv_mac;
/*if(strpos($mac,":")!==false){
    $mac = substr($mac,0,8);
    $mac = str_replace(":","-",$mac);
    $owner = exec("cat /opt/netflow/oui.txt | grep -i '".$mac."' |  awk '{ for(k=3; k<=NF; ++k) { printf \"%s \",\$k }}'");
}
else {
    $mac = substr($mac,0,6);
    $owner = exec("cat /opt/netflow/oui.txt | grep -i '".$mac."' |  awk '{ for(k=4; k<=NF; ++k) { printf \"%s \",\$k }}'");
}
*/
$mac = substr($mac,0,6);
$owner = $massiv_mac[$mac];
$owner =  str_replace(array("\r","\n"," "),"",$owner);
if ($owner == "") {$owner = "unknown";}

return $owner;
}



function SearchNameIp ($ip, $db_link) {
global $ip_netnames, $count_new,$count_error;
/*
    if($db_link) {
        $sql = "SELECT * FROM names WHERE (INET_ATON(\"".$ip."\") BETWEEN ip_start AND ip_end);";
        $result = mysqli_query($db, $sql);
        if(mysqli_num_rows($result) > 0){
            $row = mysqli_fetch_assoc($result);
            mysqli_free_result($result);
            return $row['name'];
        }else {
            $net_data = get_whois_name($ip);
            add_netname($net_data,$db_link);
            $name = key($net_data);
            $massiv_ip[]=array("ip_start" => ip2long($net_data[$name][0]),"ip_end"=>ip2long($net_data[$name][1]),"name"=>$name);
            return $name;
        }
    }

return false;
*/
    $long_ip = ip2long($ip);
    $name = "";
    foreach($ip_netnames as $value)
        {
            if($value['ip_start'] <= $long_ip && $value['ip_end'] >= $long_ip) {$name = $value['name'];  break;}
        }
    if ($name == ""){$count_new++; $net_data = get_whois_name($ip); add_netname($net_data,$db_link); $name = key($net_data);
        $ip_netnames[]=array("ip_start" => ip2long($net_data[$name][0]),"ip_end"=>ip2long($net_data[$name][1]),"name"=>$name,"descr"=>"","country"=>"");}
    return $name;

}


function add_netname ($data,$db_link)
{
    $db_link = mysqli_connect(DB_HOST, DB_USER, DB_PASS, "netname");
    $name = key($data);
    $sql = "INSERT into names (`ip_start`, `ip_end`, `name`) VALUES (INET_ATON(\"".$data[$name][0]."\"),INET_ATON(\"".$data[$name][1]."\"),'".$name."');";
    file_put_contents("/opt/netflow/sql.txt",date("d-m-Y H:i:s")."\t".$sql."\n",FILE_APPEND);
    if($data[$name][1]!=0){    $result = @mysqli_query($db_link, $sql);}
    mysqli_close($db_link);
    return $result;

}

function get_netname($whois)
{
global $count_error;
$netname = shell_exec("echo '".$whois."' | grep 'netname:' -i -m1");
if($netname == ""){$netname = shell_exec("echo '".$whois."' | grep '\[Network Name\]' -i -m1");}
if($netname == ""){$netname = shell_exec("echo '".$whois."' | grep 'owner:' -i -m1");}
if($netname == ""){$netname = shell_exec("echo '".$whois."' | grep 'Organization Name  :' -i -m1");}

if($netname == ""){$netname = "error"; $count_error++; return $netname;}
$pos = strpos($netname,"]");
if($pos === false) {$pos = strpos($netname,":");}
if($pos === false){ file_put_contents("/opt/netflow/netname.txt","cannot parse \t".$netname."\n",FILE_APPEND);
 $netname = "error2"; return $netname;}
$netname = substr($netname,$pos+1);
$netname = str_replace(array("\r","\n"," "),"",$netname);


return $netname;
}

function get_inetnum($whois)
{
$range = shell_exec("echo '".$whois."' | grep 'inetnum:' -i -m1");
if ($range == "") {$range = shell_exec("echo '".$whois."' | grep 'netrange:' -i -m1");}
if ($range == "") {$range = shell_exec("echo '".$whois."' | grep '\[Network Number\]' -i -m1");}
if ($range == "") {$range = shell_exec("echo '".$whois."' | grep 'IPv4 Address       :' -i -m1");}
if ($range == "") {$range[0]=0; $range[1]=0; return $range;}

$pos = strpos($range,"]");
if($pos === false) {$pos = strpos($range,":");}
if($pos === false){ file_put_contents("/opt/netflow/range.txt","cannot parse \t".$range."\n",FILE_APPEND);}
$range = substr($range,$pos+1);
$range = str_replace(array("\r","\n"," "),"",$range);

if(strpos($range,"-")!==false) {if(strpos($range,"(") !== false){$range = substr($range,0,strpos($range,"("));} $range=explode("-",$range);}
else if(substr_count($range, '.') == 3){$range = cidrToRange($range);}
else
    {if(substr_count($range, '.')==2)
        {$range = substr($range,0,strpos($range,"/")).".0".substr($range,strpos($range,"/"));
        $range = cidrToRange($range);}
        else if(substr_count($range, '.')==1)
            {$range = substr($range,0,strpos($range,"/")).".0.0".substr($range,strpos($range,"/"));
            $range = cidrToRange($range);}
        else {file_put_contents("/opt/netflow/range.txt",date("d-m-Y H:i:s")."\t".$range."\n",FILE_APPEND); $range[0]=0;$range[1]=0;}
    }
return $range;

}

function get_whois_name($IP)
{
$whois = shell_exec("whois ".$IP);
$whois = str_replace(array("#","\"","'"),"",$whois);
$netname = get_netname($whois);
$range = get_inetnum($whois);
if($range[0] == 0) {$range[0]=$IP; $range[1]=$IP;}

file_put_contents("/opt/netflow/whois.txt",date("d-m-Y H:i:s")."\t"."for ".$IP." \tname= ".$netname."\t \t \t \t \t \t \t range \t".$range[0]." \t- \t".$range[1]."\n",FILE_APPEND);
$result[$netname]=$range;

return $result;
}

function cidrToRange($cidr) {
  $range = array();
  $cidr = explode('/', $cidr);
  $range[0] = long2ip((ip2long($cidr[0])) & ((-1 << (32 - (int)$cidr[1]))));
  $range[1] = long2ip((ip2long($cidr[0])) + pow(2, (32 - (int)$cidr[1])) - 1);
  return $range;
}



?>
