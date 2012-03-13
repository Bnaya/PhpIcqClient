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

class packet_builder {

	var $packet_size;

	var $packet_protocol;


    /*
	 *  WORD	Type	Type of the upcoming packet must be one of these:
	 *  				0x0002	Reply on server hello
	 *  				0x0003	Loginrequest to ICQ server
	 *  				0x0004	Reply to login
	 *  				0x0005  FLAP packet
	 *  				0x0006  Close connection
	 *  				0x0007	Close connection reply
    */
	var $packet_type;


    var $packet_unknown_data;

    var $ConnSq;

	var $packet_data;

     function packet_builder($packet_type, $ConnSq) {

		$this->packet_protocol = chr(0x04).chr(0x43);

		$this->packet_type = $this->split_byte($packet_type, 2);

		$this->packet_unknown_data = str_repeat(chr(0x00), 5) . chr(0x01);

        $this->ConnSq = $this->split_byte($ConnSq, 2);

     }

     function get_packet() {

		$body = $this->packet_protocol . $this->packet_type . $this->packet_unknown_data . $this->ConnSq . $this->packet_data;

     	return $this->split_byte(strlen($body), 2) . $body;

     }

	function add_byte($byte) {
    	$this->packet_data.= chr($byte);
    }

	function add_string($string) {

    	$this->packet_data.= $string;

    }

	function add_word($word) {

    	$this->packet_data.= $this->split_byte($word, 2);

    }

	function add_dword($dword) {

		$this->packet_data.= $this->split_byte($dword, 4);

    }

	function split_byte($number, $bytes)
	{
		// If the number cannot be displayed with the chosen byte count
		if ($number >= pow(0x100, $bytes))
		{
			return false;
		}

		$splitted_bytes = '';        // the number will be saved as a string (for sending)

		for ($i = 1; $i <= $bytes; $i++)
		{
			// Zuerst bestimmen wir den Divisor f?r die aktuelle Stelle der Zahl
			$power = pow(0x100, $bytes - $i);

			$full = (int) ($number / $power);
			$splitted_bytes .= chr($full);

			// Den Rest nehmen wir als neuen Hex-Wert f?r die n�chste Schleife
			$number = $number - ($full * $power);
		}
		return $splitted_bytes;
	}


}
?>