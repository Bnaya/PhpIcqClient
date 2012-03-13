<?php
	/*****************************************************************************
	 *****************************************************************************
	 *
	 * Sends and gets packets wraped in http requeste from ICQ http proxy server.
	 *  Packets to send and receive look like this:
	 *
	 *  WORD	Size	Size of the upcoming packet
	 *  WORD	Version	Version of the ICQ Proxy Protocol (always 0x0443)
	 *  WORD	Type	Type of the upcoming packet must be one of these:
	 *  				0x0002	Reply on server hello
	 *  				0x0003	Loginrequest to ICQ server
	 *  				0x0004	Reply to login
	 *  				0x0005  FLAP packet
	 *  				0x0006  Close connection
	 *  				0x0007	Close connection reply
	 *  DWORD	Unkn	0x00000000
	 *  WORD	Unkn	0x0000
	 *  WORD	ConnSq	Number of connection the packet is for
	 *  ...		Data	Data of the packet (Size - 14 bytes)
	 *
	 *****************************************************************************
	 *****************************************************************************/
class packet_reader extends raw_reader {
	
	var $raw;

	var $packets = array();
	
    /*var $size; //WORD
    
    var $version; //WORD
    
    var $type; //WORD
    
    var $ConnSeq; //WORD
    
    var $data; //size - 12 or 14, im not sure yet*/


	function packet_reader($raw) {

    	$this->raw = $raw;
    	$this->set_readFrom($this->raw);

    }
    
    function analyze() {
    	
    	while($this->pointer < (strlen($this->raw) -1)) {
    	
    	$packet = new aim_http_packet();
    	
    	$packet->size = $this->fget_word();
    	
    	$packet->version = $this->fget_word();
    	
    	$packet->type = $this->fget_word();
    	
       	//over read unknown data
    	
    	$this->fget_dword();
    	$this->fget_word();

    	$packet->ConnSeq = $this->fget_word();    	
    	
    	$packet->data = '';
    	
    	if(($packet->size - 12) > 0) {
    		
    		$packet->data = $this->fget_string($packet->size - 12);

    		$a = strlen($packet->data);   		
    		
    	}
    	
    	$this->packets[] = $packet;
    	
    	}
    	
    }

}
?>