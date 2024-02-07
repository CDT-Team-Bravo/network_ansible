<?php
require_once("/etc/inc/interfaces.inc");
$portlist = get_interface_list();
$lagglist = get_lagg_interface_list();
$portlist = array_merge($portlist, $lagglist);
foreach ($lagglist as $laggif => $lagg) {    
    $laggmembers = explode(',', $lagg['members']);
    foreach ($laggmembers as $lagm)        
        if (isset($portlist[$lagm])) unset($portlist[$lagm]);
}
$list = array();
foreach ($portlist as $ifn => $ifinfo) {  
    $list[$ifn] = $ifn . " (\" . $ifinfo[\"mac\"] . \")";
    $iface = convert_real_interface_to_friendly_interface_name($ifn);
    if (isset($iface) && strlen($iface) > 0) $list[$ifn] .= " - $iface";
}
echo json_encode($list);
?>