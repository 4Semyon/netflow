#!/usr/bin/php -q
<?php
include('config.php');
include('functions.php');

error_reporting(0);
if(file_exists("/opt/netflow/lock")){exit;}
else{file_put_contents("/opt/netflow/lock",'1'."\n",FILE_APPEND);}

$start_time=time();

$clients = get_clients(3900);
$ip_netnames = get_ip_netnames();
$mac_owners = get_macowners();

//exit();

$count_records=0;
$count_new_ip = 0;
$count_error_ip = 0;

//$db_link = mysqli_connect(DB_HOST, DB_USER, DB_PASS, "netname");

exec("nfdump -r ".$argv[2]."  -o \"fmt:%ts;%te;%pr;%sa;%sp;%da;%dp;%ismc;%osmc;%pkt;%byt;%bpp\"",$ret_arr);
//2016-08-24T02:44:37+0300 2016-08-24T02:44:37+0300 TCP 10.0.6.62 59160 2.21.7.43 80 94d8597bcdac a0369f51a7dd 1 52 74996371497 0 AKAMAI-PA TCTmobileltd
//echo strtotime("2016-08-24T02:44:37+0300");

foreach($ret_arr as $value){
    $massiv = explode(";",$value);
    if(isset($massiv[11])){
    $count_records++;
    $date_start=strtotime($massiv[0]);
    $date_stop=strtotime($massiv[1]);
    $protocol=str_replace(" ","",$massiv[2]);
    $ip_from=str_replace(" ","",$massiv[3]);
    $port_from=str_replace(" ","",$massiv[4]);
    $ip_to=str_replace(" ","",$massiv[5]);
    $port_to=str_replace(" ","",$massiv[6]);
    $mac_in=str_replace(":","",$massiv[7]);
    $mac_out=str_replace(":","",$massiv[8]);
    $packets=str_replace(" ","",$massiv[9]);
    $bytes=str_replace(" ","",$massiv[10]);
    $bytes_in_packet=str_replace(" ","",$massiv[11]);

    if( isset($clients[$mac_src]) && isset($clients[$mac_dst])) {$number = $clients[$mac_src].";".$clients[$mac_dst];}
    else if (isset($clients[$mac_src]) && !isset($clients[$mac_dst])) {$number = $clients[$mac_src];}
    else if (!isset($clients[$mac_src]) && isset($clients[$mac_dst])) {$number = $clients[$mac_dst];}
    else {$number="unknown"; file_put_contents("/opt/netflow/mac_unknown.txt","NO found number for \t".$mac_src." or ".$mac_dst."\n",FILE_APPEND);}

    $duration = get_duration_session($massiv[0],$massiv[1]);

    if(strpos($massiv[3],"10.0.")!==false){$ip=$massiv[5]; $mac_owner=get_mac_owner($massiv[7]); }else{$ip=$massiv[3]; $mac_owner=get_mac_owner($massiv[8]);}

    $netname = SearchNameIp($ip, $db_link);

//    file_put_contents("/opt/netflow/time.txt","Search ".$ip." ".(time()-$s)."\n",FILE_APPEND);

//    if(!$netname){$net_data = get_whois_name($ip); add_netname($net_data,$db_link); $netname = key($net_data);}
    file_put_contents("/opt/netflow/flows/".basename($argv[2]).".txt",'netflow: '.$date_start.' '.$date_stop.' '.$massiv[2].' '.$massiv[3].' '.$massiv[4].' '.$massiv[5].' '.$massiv[6].' '.$mac_src.' '.$mac_dst.' '.$massiv[9].' '.$massiv[10].' '.$number.' '.$duration.' '.$netname.' '.$mac_owner."\n",FILE_APPEND);

    //send_remote_syslog('netflow: '.$date_start.' '.$date_stop.' '.$massiv[2].' '.$massiv[3].' '.$massiv[4].' '.$massiv[5].' '.$massiv[6].' '.$mac_src.' '.$mac_dst.' '.$massiv[9].' '.$massiv[10].' '.$number.' '.$duration.' '.$netname);

    }
}

//mysqli_close($db_link);

exec("unlink /opt/netflow/lock");

log_it("File: '".$argv[2].", records: ".$count." execute time:".(time()-$start_time). " count_new:".$count_new." count_error:".$count_error);


?>
