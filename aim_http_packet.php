<?php
class aim_http_packet extends basic {
	
	var $size; //WORD
    
    var $version; //WORD
    
    var $type; //WORD
    
    var $ConnSeq; //WORD
    
    var $data; //size - 12 or 14, im not sure yet
}
?>